import os
import time
from unittest import mock

import jwt
import pytest

from src import set_cookie


def test_validate():
    with mock.patch('src.set_cookie.get_jwt_secret') as jwt_s:
        jwt_s.return_value = 'foobar'

        event = {}
        with pytest.raises(KeyError):
            set_cookie.validate_request(event)

        event['queryStringParameters'] = {
            'token': '',
            'domain': 'example.org',
        }
        with pytest.raises(jwt.InvalidTokenError):
            set_cookie.validate_request(event)

        event['queryStringParameters']['token'] = jwt.encode(
            {},
            'different key' + jwt_s.return_value,
            'HS256'
        )
        with pytest.raises(jwt.InvalidTokenError):
            set_cookie.validate_request(event)

        event['queryStringParameters']['token'] = jwt.encode(
            {},
            jwt_s.return_value,
            'HS256'
        )
        with pytest.raises(KeyError):
            set_cookie.validate_request(event)

        event['queryStringParameters']['token'] = jwt.encode(
            {
                'exp': time.time() - 1,
                'domains': [],
            },
            jwt_s.return_value,
            'HS256'
        )
        with pytest.raises(jwt.ExpiredSignatureError):
            set_cookie.validate_request(event)

        in_5_seconds = int(time.time() + 5)
        event['queryStringParameters']['token'] = jwt.encode(
            {
                'exp': in_5_seconds,
                'domains': ['example.com'],
            },
            jwt_s.return_value,
            'HS256'
        )
        with pytest.raises(ValueError):
            set_cookie.validate_request(event)

        event['queryStringParameters']['token'] = jwt.encode(
            {
                'exp': in_5_seconds,
                'domains': ['example.org', 'example.net'],
            },
            jwt_s.return_value,
            'HS256'
        )
        ret = set_cookie.validate_request(event)

        assert isinstance(ret, set_cookie.SetCookieRequest)
        assert ret.domain == 'example.org'
        assert ret.expire == in_5_seconds


def test_handler():
    with mock.patch('src.set_cookie.validate_request') as vr:
        vr.return_value = set_cookie.SetCookieRequest(
            raw_token='xxxxxxxx',
            domain='example.org',
            expire=int(time.time()),
            return_to=None,
        )
        os.environ['DOMAIN_NAME'] = 'auth.example.org'

        ret = set_cookie.handler({}, None)

        assert ret['statusCode'] == 200
        set_cookie_headers = []
        for k, v in ret['headers'].items():
            if k.lower() == 'set-cookie':
                set_cookie_headers.append(v)
        assert len(set_cookie_headers) == 1


def test_generate_cookies():
    cookies = set_cookie.generate_cookie_headers(set_cookie.SetCookieRequest(
        raw_token='xxxxxxxx',
        domain='example.org',
        expire=int(time.time()),
        return_to=None,
    ))
    assert len(cookies) == 1
