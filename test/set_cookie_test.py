import json
import os
import time
from unittest import mock

import jwt
import pytest
import rsa

from src import set_cookie

test_keypair = {
    'private': """\
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDYDRTsbDmjdFKqparYnJeeYuixSSTo1nY55cFDnFmt45FBV0ne
hIftF6SxxV/Wk/EI5y5HdVzfoQQrK8CmYAPnIpsSmchOPhUcWBU6QwFaYSXLHITD
sQ5rNiTFqprOGDorzvBnHoS3wYwLtXm7avepebIEKdt88DDTWuxuGJwVVwIDAQAB
AoGARbGqnz2mNkEu7Zd1jlytWE2FzLLQsj+EcdbYykukbkCruc1DqgFMq8Hlwebu
rJSau4l/11NXu1gAtUBu6/yrJQt+4YF4m648sQkgtQHQTnp9aickhJHN7NwwEWIo
XRYOGti729K4AxjfNpTctruoSFt/QHoG4J3qQWD+ZRJijEECQQD40wCFt6CPAtam
3wKQGDpW9qr8u0KaBBPlpnPJbSnf/n7xKtn/2T13I2RXOUz/lRYpsE8kO9FG5E3k
1fiRQbrhAkEA3kggBh0vdbGQqYy/glAPyq9UYW9XxQTcE/kAyCCiHqTknm6jERXY
zdy6EFZzYTaSDkuAL6/Ky+iRlF0H0oHPNwJAKIalRSIdQm2h7FfSIQnxJozSWItf
U5pqazLrFNl0woi+wCTMkMEfI7Jd+17XzaDIlU2j9jDP6w3wKd83tuDPwQJAGgt7
bRv4VqMCn0s1mVBGOWqHyY7hSt2B5/kyJUDlng+WFhZClxrnN1/YkVd/13Esde5U
y8GeUnwiqq6n3vuEywJBAJiYcMP9h8TqQrKNyikcWxgFq95x/uWzP9L+z2AgoY+C
rlDCBvcLuV9mCftxKzukqvHIYTWpUFCi1VEVVfVWXKE=
-----END RSA PRIVATE KEY-----
""",
    'public': """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANgNFOxsOaN0Uqqlqticl55i6LFJJOjWdjnlwUOcWa3jkUFXSd6Eh+0X
pLHFX9aT8QjnLkd1XN+hBCsrwKZgA+cimxKZyE4+FRxYFTpDAVphJcschMOxDms2
JMWqms4YOivO8GcehLfBjAu1ebtq96l5sgQp23zwMNNa7G4YnBVXAgMBAAE=
-----END RSA PUBLIC KEY-----
""",
}


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
