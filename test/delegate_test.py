import time
from unittest import mock

import jwt

import delegate
import utils


def test_no_token():
    cognito_url = 'https://cognito/'
    with mock.patch('delegate.get_refresh_token', side_effect=utils.NotLoggedIn), \
         mock.patch('utils.get_jwt_secret', return_value='secret'), \
         mock.patch('utils.cognito_url', return_value=cognito_url):
        resp = delegate.handler({}, None)
        assert 302 == resp['statusCode']
        assert cognito_url == resp['headers']['Location']


def test_bad_token():
    with mock.patch('delegate.get_refresh_token', side_effect=utils.BadRequest):
        resp = delegate.handler({}, None)
        assert 400 == resp['statusCode']


def gen_refresh_token(domain: str, exp_in: int = 5):
    now = int(time.time())
    return {
        'iat': now,
        'exp': now + exp_in,
        'azp': 'test',
        'domains': [domain],
    }


def test_post():
    now = int(time.time())
    refresh_token = gen_refresh_token('example.org')
    body = f"exp={now+1}&subject=sub&example.org=on"
    with mock.patch('delegate.get_refresh_token', return_value=refresh_token), \
            mock.patch('delegate.is_allowed_domain', side_effect=lambda d: d in {'example.org'}), \
            mock.patch('utils.get_jwt_secret', return_value='secret'):
        resp = delegate.handler({
            'httpMethod': 'POST',
            'body': body,
        }, None)
        assert 200 == resp['statusCode']


def test_post_too_long():
    now = int(time.time())
    refresh_token = gen_refresh_token('example.org')
    body = f"exp={now+10}&subject=sub&example.org=on"
    with mock.patch('delegate.get_refresh_token', return_value=refresh_token), \
         mock.patch('delegate.is_allowed_domain', side_effect=lambda d: d in {'example.org'}), \
         mock.patch('utils.get_jwt_secret', return_value='secret'):
        resp = delegate.handler({
            'httpMethod': 'POST',
            'body': body,
        }, None)
        assert 400 == resp['statusCode']


def test_post_domain_outside_list():
    now = int(time.time())
    refresh_token = gen_refresh_token('example.com')
    body = f"exp={now+1}&subject=sub&example.com=on"
    with mock.patch('delegate.get_refresh_token', return_value=refresh_token), \
         mock.patch('delegate.is_allowed_domain', side_effect=lambda d: d in {'example.org'}), \
         mock.patch('utils.get_jwt_secret', return_value='secret'):
        resp = delegate.handler({
            'httpMethod': 'POST',
            'body': body,
        }, None)
        assert 400 == resp['statusCode']


def test_domain_outside_token():
    now = int(time.time())
    refresh_token = gen_refresh_token('example.org')
    body = f"exp={now+1}&subject=sub&example.com=on"
    with mock.patch('delegate.get_refresh_token', return_value=refresh_token), \
         mock.patch('delegate.is_allowed_domain',
                    side_effect=lambda d: d in {'example.org', 'example.com'}), \
         mock.patch('utils.get_jwt_secret', return_value='secret'):
        resp = delegate.handler({
            'httpMethod': 'POST',
            'body': body,
        }, None)
        assert 400 == resp['statusCode']


def test_post_no_subject():
    now = int(time.time())
    refresh_token = gen_refresh_token('example.org')
    body = f"exp={now+1}&subject=&example.org=on"
    with mock.patch('delegate.get_refresh_token', return_value=refresh_token), \
         mock.patch('delegate.is_allowed_domain', side_effect=lambda d: d in {'example.org'}), \
         mock.patch('utils.get_jwt_secret', return_value='secret'):
        resp = delegate.handler({
            'httpMethod': 'POST',
            'body': body,
        }, None)
        assert 400 == resp['statusCode']


def test_sub_delegate():
    now = int(time.time())
    refresh_token = gen_refresh_token('example.org')
    refresh_token['sub'] = ['test1']
    body = f"exp={now+1}&subject=test2&example.org=on"
    with mock.patch('delegate.get_refresh_token', return_value=refresh_token), \
         mock.patch('delegate.is_allowed_domain', side_effect=lambda d: d in {'example.org'}), \
         mock.patch('utils.get_jwt_secret', return_value='secret'):
        resp = delegate.handler({
            'httpMethod': 'POST',
            'body': body,
        }, None)
        assert 200 == resp['statusCode']
        delegate_token = jwt.decode(resp['body'], 'secret', algorithms=["HS256"], options={"verify_signature": False})
        assert 'test1' in delegate_token['sub']
