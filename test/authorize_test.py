from dataclasses import dataclass
from typing import ClassVar
from unittest import mock

import pytest

import authorize
import utils

from .test_utils import gen_refresh_token


@dataclass
class LambdaContext:
    function_name: str = "test"
    memory_limit_in_mb: int = 128
    invoked_function_arn: str = "arn:aws:lambda:eu-west-1:809313241:function:test"
    aws_request_id: str = "52fdfc07-2182-154f-163f-5f0f9a621d72"


@pytest.fixture
def lambda_context() -> LambdaContext:
    return LambdaContext()


def test_no_redirect_uri(lambda_context):
    resp = authorize.handler({}, lambda_context)
    assert resp['statusCode'] == 400


def test_not_logged_in(lambda_context):
    cognito_url = 'https://cognito/'
    with mock.patch('authorize.get_refresh_token', side_effect=utils.NotLoggedIn), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('utils.cognito_url', return_value=cognito_url):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, lambda_context)
        assert resp['statusCode'] == 302
        assert cognito_url == resp['headers']['Location']


def test_bad_request(lambda_context):
    with mock.patch('authorize.get_refresh_token', side_effect=utils.BadRequest):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, lambda_context)
        assert resp['statusCode'] == 400


def test_normal(lambda_context):
    refresh_token = gen_refresh_token('example.org')
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, lambda_context)
        assert resp['statusCode'] == 302
        assert resp['headers']['Location'].startswith('https://example.org/')


def test_wrong_domain(lambda_context):
    refresh_token = gen_refresh_token('example.com')
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, lambda_context)
        assert resp['statusCode'] == 400


def test_no_exp(lambda_context):
    refresh_token = gen_refresh_token('example.org')
    del refresh_token['exp']  # no exp
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, lambda_context)
        assert resp['statusCode'] == 400


def test_no_azp(lambda_context):
    refresh_token = gen_refresh_token('example.org')
    del refresh_token['azp']
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, lambda_context)
        assert resp['statusCode'] == 400


def test_unlisted_domain(lambda_context):
    refresh_token = gen_refresh_token(domain=None)
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.com/',
            },
        }, lambda_context)
        assert resp['statusCode'] == 400
