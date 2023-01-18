import json
import time
from unittest import mock

import jwt
import jwt.utils
import pytest

from src import utils


def test_canon_header():
    assert utils.canonicalize_headers({
            'Cookie': 'foo',
            'cookie': 'bar',
        }) == {
            'cookie': ['foo', 'bar']
        }

    assert utils.canonicalize_headers([
            ('Cookie', 'foo'),
            ('cookie', 'bar'),
        ]) == {
            'cookie': ['foo', 'bar']
        }


def test_refresh_token_no_cookie():
    with pytest.raises(utils.NotLoggedIn):
        token = utils.get_refresh_token({
            'headers': {}
        })


def test_refresh_token_other_cookie():
    with pytest.raises(utils.NotLoggedIn):
        token = utils.get_refresh_token({
            'headers': {
                'Cookie': 'foo=bar',
            }
        })


def test_refresh_token_invalid_token():
    with mock.patch('src.utils.get_refresh_token_jwt_secret', return_value="secret"):
        with pytest.raises(utils.BadRequest):
            token = utils.get_refresh_token({
                'headers': {
                    'Cookie': f"{utils.get_config().cookie_name_refresh_token}=foobar",
                }
            })


def test_refresh_token_expired_token():
    now = time.time()
    raw_token = jwt.encode(
        {
            'iat': now-1,
            'exp': now-2,
            'azp': 'test',
        },
        'secret',
        algorithm='HS256',
    )
    with mock.patch('src.utils.get_refresh_token_jwt_secret', return_value="secret"):
        with pytest.raises(utils.NotLoggedIn):
            token = utils.get_refresh_token({
                'headers': {
                    'Cookie': f"{utils.get_config().cookie_name_refresh_token}={raw_token}",
                }
            })


def test_refresh_token_valid_token():
    now = time.time()
    in_token = {'iat': now-1, 'exp': now + 5, 'azp': 'test', }
    raw_token = jwt.encode(
        in_token,
        'secret',
        algorithm='HS256',
    )
    with mock.patch('src.utils.get_refresh_token_jwt_secret', return_value="secret"):
        token = utils.get_refresh_token({
            'headers': {
                'Cookie': f"{utils.get_config().cookie_name_refresh_token}={raw_token}",
            }
        })
        assert in_token == token


def test_refresh_token_unsigned_token():
    now = time.time()
    in_token = {'iat': now, 'exp': now + 5, 'azp': 'test', }
    raw_token = \
        jwt.utils.base64url_encode(json.dumps({
            "typ": "JWT",
            "alg": "None",
        }).encode('utf-8')).decode('utf-8') + \
        '.' + \
        jwt.utils.base64url_encode(json.dumps(in_token).encode('utf-8')).decode('utf-8') + \
        '.' + \
        ''  # no signature
    with mock.patch('src.utils.get_refresh_token_jwt_secret', return_value="secret"):
        with pytest.raises(utils.BadRequest):
            utils.get_refresh_token({
                'headers': {
                    'Cookie': f"{utils.get_config().cookie_name_refresh_token}={raw_token}",
                }
            })
