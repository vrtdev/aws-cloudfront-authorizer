import json
from unittest import mock

import jwt

import generate_ci


def test_post():
    body = { "exp_in": 60 * 60, "subject": "sub", "domains": ["example.org", "another-example.org"] }
    with mock.patch('generate_ci.is_allowed_domain', side_effect=lambda d: d in {'example.org', 'another-example.org'}), \
            mock.patch('generate_ci.get_access_token_jwt_secret', return_value='secret'):
        resp = generate_ci.handler({
            'httpMethod': 'POST',
            'requestContext': { 'identity': { 'caller': "test" }},
            'body': json.dumps(body),
        }, None)
        assert 200 == resp['statusCode']
        ci_token = jwt.decode(resp['body'], 'secret', algorithms=["HS256"], options={"verify_signature": False})
        assert 'example.org' in ci_token['domains']
        assert 'another-example.org' in ci_token['domains']


def test_post_too_long():
    body = { "exp_in": 60 * 60 * 10, "subject": "sub", "domains": ["example.org"] }
    with mock.patch('generate_ci.is_allowed_domain', side_effect=lambda d: d in {'example.org'}), \
            mock.patch('generate_ci.get_access_token_jwt_secret', return_value='secret'):
        resp = generate_ci.handler({
            'httpMethod': 'POST',
            'requestContext': { 'identity': { 'caller': "test" }},
            'body': json.dumps(body),
        }, None)
        assert 400 == resp['statusCode']


def test_post_domain_outside_list():
    body = { "exp_in": 60 * 60, "subject": "sub", "domains": ["example.com"] }
    with mock.patch('generate_ci.is_allowed_domain', side_effect=lambda d: d in {'example.org'}), \
            mock.patch('generate_ci.get_access_token_jwt_secret', return_value='secret'):
        resp = generate_ci.handler({
            'httpMethod': 'POST',
            'requestContext': { 'identity': { 'caller': "test" }},
            'body': json.dumps(body),
        }, None)
        assert 400 == resp['statusCode']


def test_post_no_subject():
    body = { "exp_in": 60 * 60, "domains": ["example.com"] }
    with mock.patch('generate_ci.is_allowed_domain', side_effect=lambda d: d in {'example.org'}), \
            mock.patch('generate_ci.get_access_token_jwt_secret', return_value='secret'):
        resp = generate_ci.handler({
            'httpMethod': 'POST',
            'requestContext': { 'identity': { 'caller': "test" }},
            'body': json.dumps(body),
        }, None)
        assert 400 == resp['statusCode']
