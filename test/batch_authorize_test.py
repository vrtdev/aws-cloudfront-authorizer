import json
from unittest import mock

import batch_authorize
from .utils import gen_refresh_token


def test_normal():
    refresh_token = gen_refresh_token('example.org')
    with mock.patch('batch_authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'):
        resp = batch_authorize.handler({}, None)
        assert 200 == resp['statusCode']
        body = resp['body']
        tokens = json.loads(body)
        assert isinstance(tokens, dict)
        assert 'example.org' in tokens
