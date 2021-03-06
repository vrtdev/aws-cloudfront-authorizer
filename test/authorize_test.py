from unittest import mock

import authorize
import utils
from .utils import gen_refresh_token


def test_no_redirect_uri():
    resp = authorize.handler({}, None)
    assert 400 == resp['statusCode']


def test_not_logged_in():
    cognito_url = 'https://cognito/'
    with mock.patch('authorize.get_refresh_token', side_effect=utils.NotLoggedIn), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('utils.cognito_url', return_value=cognito_url):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, None)
        assert 302 == resp['statusCode']
        assert cognito_url == resp['headers']['Location']


def test_bad_request():
    with mock.patch('authorize.get_refresh_token', side_effect=utils.BadRequest):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, None)
        assert 400 == resp['statusCode']


def test_normal():
    refresh_token = gen_refresh_token('example.org')
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, None)
        assert 302 == resp['statusCode']
        assert resp['headers']['Location'].startswith('https://example.org/')


def test_wrong_domain():
    refresh_token = gen_refresh_token('example.com')
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, None)
        assert 400 == resp['statusCode']


def test_no_exp():
    refresh_token = gen_refresh_token('example.org')
    del refresh_token['exp']  # no exp
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, None)
        assert 400 == resp['statusCode']


def test_no_azp():
    refresh_token = gen_refresh_token('example.org')
    del refresh_token['azp']
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.org/',
            },
        }, None)
        assert 400 == resp['statusCode']


def test_unlisted_domain():
    refresh_token = gen_refresh_token(domain=None)
    with mock.patch('authorize.get_refresh_token', return_value=refresh_token), \
            mock.patch('utils.get_jwt_secret', return_value='secret'), \
            mock.patch('authorize.is_allowed_domain', side_effect=lambda d: d in {'example.org'}):
        resp = authorize.handler({
            'queryStringParameters': {
                'redirect_uri': 'https://example.com/',
            },
        }, None)
        assert 400 == resp['statusCode']
