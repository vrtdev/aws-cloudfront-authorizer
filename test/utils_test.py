from unittest import mock

import jwt

from src import utils


def test_case_variants():
    assert list(utils.generate_case_variants('Tes')) == \
           ['Tes', 'TeS', 'TEs', 'TES', 'tes', 'teS', 'tEs', 'tES']


def test_case_variants_nonalpha():
    assert list(utils.generate_case_variants('a-b')) == \
        ['a-b', 'a-B', 'A-b', 'A-B']


def test_case_variants_long():
    it = utils.generate_case_variants(70 * 'a').__iter__()
    assert it.__next__() == 70 * 'a'
    assert it.__next__() == 69 * 'a' + 'A'
    assert it.__next__() == 68 * 'a' + 'Aa'
    assert it.__next__() == 68 * 'a' + 'AA'


def test_base64():
    assert utils.aws_web_safe_base64_encode(b'tes') == 'dGVz'
    assert utils.aws_web_safe_base64_encode(b'test') == 'dGVzdA__'
    assert utils.aws_web_safe_base64_encode(b'\xff\xe0') == '~-A_'


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


def test_validate_cookie():
    with mock.patch('src.utils.get_jwt_secret', return_value='foobar') as jwt_sec:
        token_in = {'foo': 'bar'}
        cookie = jwt.encode(token_in, jwt_sec.return_value, 'HS256').decode('ascii')

        token_out = utils.validate_login_cookie({
            'headers': {
                'Cookie': f'{utils.VRT_AUTH_LOGIN_COOKIE_NAME}={cookie}'
            }
        })
        assert token_in == token_out


def test_origin():
    assert utils.url_origin('https://foobar.com/whatever') == 'https://foobar.com'
