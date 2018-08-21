import os
import re
import time
from unittest import mock

import jwt
import pytest

from src import request_access


def test_validate():
    with pytest.raises(KeyError):
        request_access.validate_request({})

    req = request_access.validate_request({
        'body': 'exp=42'
    })
    assert req.expire == 42
    assert req.domains == set()

    with mock.patch('src.request_access.known_domains', return_value=['example.org', 'example.com']):
        req = request_access.validate_request({
            'body': 'exp=42&example.org=on&example.com=checked'
        })
    assert req.expire == 42
    assert req.domains == {'example.com', 'example.org'}

    with pytest.raises(ValueError):
        request_access.validate_request({
            'body': f'exp={int(time.time())+400*24*60*60}&example.org=on&example.com=checked'
        })

    with pytest.raises(ValueError):
        request_access.validate_request({
            'body': 'exp=42&example.org/foobar=on&example.com=checked'
        })


def test_url():
    with mock.patch('src.request_access.get_jwt_secret') as jwt_s:
        jwt_s.return_value = 'foobar'

        in_5_seconds = int(time.time()) + 5
        url = request_access.generate_url(
            url_prefix='https://localhost/',
            login_cookie={'azp': 'test'},
            request=request_access.GenerateJwtRequest(
                expire=in_5_seconds,
                domains={'example.com', 'example.org'},
            )
        )

        assert url.startswith('https://localhost/grant_access?token=')

        token = url[37:]
        token = jwt.decode(token, jwt_s.return_value)
        assert token['exp'] == in_5_seconds
        assert set(token['domains']) == {'example.com', 'example.org'}


def test_handler():
    with mock.patch('src.request_access.validate_request') as req, \
            mock.patch('src.request_access.get_jwt_secret', return_value='foobar'),\
            mock.patch('src.request_access.validate_login_cookie', return_value={'azp': 'test'}):
        in_5_seconds = int(time.time()) + 5
        req.return_value = request_access.GenerateJwtRequest(
            expire=in_5_seconds,
            domains={'example.com', 'example.net'}
        )
        os.environ['DOMAIN_NAME'] = 'auth.example.org'

        ret = request_access.handler(
            {
                'requestContext': {
                    'apiId': 'foo',
                    'stage': 'Prod',
                },
                'headers': {'HOST': 'foobar'},
                'body': 'exp=42&example.org=on',
            },
            None
        )
        assert ret['statusCode'] == 200
        assert re.search(r'https://[^/]*/[^?]*\?token=', ret['body'])
