from unittest import mock

import jwt

import generate_master

@mock.patch('generate_master.put_master_parameter')
def test_master_token_generation(put_master_parameter_mocked):
    with mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('generate_master.get_domains', return_value=["example.org", "another-example.org"]):
        resp = generate_master.handler({}, None)
        assert 200 == resp['statusCode']
        master_token = jwt.decode(put_master_parameter_mocked.call_args.args[0], 'secret', algorithms=["HS256"], options={"verify_signature": False})
        assert 'example.org' in master_token['domains']
        assert 'another-example.org' in master_token['domains']
