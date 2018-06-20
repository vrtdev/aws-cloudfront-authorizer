import os
import re
from unittest import mock

import jwt
import pytest

from src import grant_access


def test_validate():
    with mock.patch('src.grant_access.get_jwt_secret') as jwt_s:
        jwt_s.return_value = 'foobar'

        event = {}
        with pytest.raises(KeyError):
            grant_access.validate_request(event)

        event['queryStringParameters'] = {
            'token': '',
        }
        with pytest.raises(jwt.InvalidTokenError):
            grant_access.validate_request(event)

        event['queryStringParameters']['token'] = jwt.encode(
            {},
            'different key' + jwt_s.return_value,
            'HS256'
        )
        with pytest.raises(jwt.InvalidTokenError):
            grant_access.validate_request(event)

        event['queryStringParameters']['token'] = jwt.encode(
            {},
            jwt_s.return_value,
            'HS256'
        )
        with pytest.raises(KeyError):
            grant_access.validate_request(event)

        event['queryStringParameters']['token'] = jwt.encode(
            {
                'domains': [],
            },
            jwt_s.return_value,
            'HS256'
        )
        ret = grant_access.validate_request(event)

        assert isinstance(ret, grant_access.GrantAccessRequest)
        assert set(ret.domains) == set()

        event['queryStringParameters']['token'] = jwt.encode(
            {
                'domains': ['example.com', 'example.org'],
            },
            jwt_s.return_value,
            'HS256'
        )
        ret = grant_access.validate_request(event)

        assert isinstance(ret, grant_access.GrantAccessRequest)
        assert set(ret.domains) == {'example.com', 'example.org'}


def test_handler():
    with mock.patch('src.grant_access.validate_request') as vr:
        vr.return_value = grant_access.GrantAccessRequest(
            token={'exp': 0},
            raw_token='<JWT>',
            domains={'example.org', 'example.com'},
        )

        os.environ['MAGIC_PATH'] = "/set-cookie-1234"
        ret = grant_access.handler({}, None)

        assert ret['statusCode'] == 200
        assert ret['body'] != ''
