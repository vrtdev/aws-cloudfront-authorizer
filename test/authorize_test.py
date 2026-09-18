from unittest import mock

import pytest

import authorize
import utils

from .test_utils import LambdaContext, gen_refresh_token


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
