import json
from unittest import mock

import pytest

import batch_authorize

from .test_utils import LambdaContext, gen_refresh_token


@pytest.fixture
def lambda_context() -> LambdaContext:
    return LambdaContext()

def test_normal(lambda_context):
    refresh_token = gen_refresh_token('example.org')
    with mock.patch('batch_authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'):
        resp = batch_authorize.handler({}, lambda_context)
        assert resp['statusCode'] == 200
        body = resp['body']
        tokens = json.loads(body)
        assert isinstance(tokens, dict)
        assert 'example.org' in tokens
