import time
from unittest import mock

import jwt
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
            'iat': now,
            'exp': now-1,
            'azp': 'test',
        },
        'secret',
        algorithm='HS256',
    ).decode('ascii')
    with mock.patch('src.utils.get_refresh_token_jwt_secret', return_value="secret"):
        with pytest.raises(utils.NotLoggedIn):
            token = utils.get_refresh_token({
                'headers': {
                    'Cookie': f"{utils.get_config().cookie_name_refresh_token}={raw_token}",
                }
            })


def test_refresh_token_valid_token():
    now = time.time()
    in_token = {'iat': now, 'exp': now + 5, 'azp': 'test', }
    raw_token = jwt.encode(
        in_token,
        'secret',
        algorithm='HS256',
    ).decode('ascii')
    with mock.patch('src.utils.get_refresh_token_jwt_secret', return_value="secret"):
        token = utils.get_refresh_token({
            'headers': {
                'Cookie': f"{utils.get_config().cookie_name_refresh_token}={raw_token}",
            }
        })
        assert in_token == token
