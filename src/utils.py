import base64
import functools
import os
import typing
from http import cookies

import boto3
import jwt
import structlog


VRT_AUTH_LOGIN_COOKIE_NAME = 'VRT_authorizer_login'
VRT_AUTH_ACCESS_COOKIE_NAME = 'VRT_authorizer_access'
# WARNING: ^^^^^ also hard-coded in index.js!!!


@functools.lru_cache(maxsize=1)
def get_jwt_secret() -> str:
    # Don't do this at the module level
    # That would make running tests with Mocked SSM much harder
    _jwt_secret = boto3.client('ssm').get_parameter(
        Name=os.environ['JWT_SECRET_PARAMETER_NAME'],
        WithDecryption=True,
    )
    return _jwt_secret['Parameter']['Value']


def canonicalize_headers(
        headers: typing.Union[typing.Dict[str, str], typing.List[typing.Tuple[str, str]]]
) -> typing.Dict[str, typing.List[str]]:
    if isinstance(headers, dict):
        headers = [
            (k, v)
            for k, v in headers.items()
        ]

    canonical_headers = dict()
    for name, value in headers:
        name = name.lower()
        if name not in canonical_headers:
            canonical_headers[name] = []
        canonical_headers[name].append(value)

    return canonical_headers


def generate_case_variants(header_name: str) -> typing.Iterable[str]:
    swapped_header_name = header_name.swapcase()

    swappable_letters = []
    for i in range(len(header_name)):
        if header_name[i] != swapped_header_name[i]:
            swappable_letters.append(i)

    # Start by swapping the last letters first. This optimizes for humans reading
    # responses by hand in quickly visually recognizing the headers.
    swappable_letters = list(reversed(swappable_letters))

    if len(swappable_letters) > 63:
        # For academic purposes only. We won't ever iterate over 2**64 entries anyway
        swappable_letters = swappable_letters[0:64]

    for variant in range(2 ** len(swappable_letters)):
        output = list(header_name)
        for swap_index, string_index in enumerate(swappable_letters):
            if variant & (1 << swap_index):
                output[string_index] = swapped_header_name[string_index]
        yield ''.join(output)


class NotLoggedInError(Exception):
    pass


def validate_login_cookie(event: dict) -> dict:
    """
    Validates the login cookie.
    Returns the decoded token, or raises NotLoggedInError.
    :raises: NotLoggedInError
    """
    headers = canonicalize_headers(event['headers'])

    try:
        request_cookies = cookies.BaseCookie(headers['cookie'][0])
        login_token = request_cookies[VRT_AUTH_LOGIN_COOKIE_NAME].value

        token = jwt.decode(  # may raise
            login_token,
            key=get_jwt_secret(),
            algoritms=['HS256'],
            verify=True,
        )
        structlog.get_logger().log("Valid login token found", jwt=token)
        return token
    except KeyError as e:
        raise NotLoggedInError("No login cookie found") from e
    except jwt.exceptions.InvalidTokenError as e:
        raise NotLoggedInError("Invalid login cookie") from e


def aws_web_safe_base64_encode(plain: typing.Union[bytes, str]) -> str:
    if isinstance(plain, str):
        plain = plain.encode('utf-8')

    normal_b64 = base64.b64encode(plain).decode('ascii')
    # The `altchars` parameter of b64encode() is useless, since we need to convert the `=` as well
    websafe_b64 = normal_b64.translate(
        {ord('+'): '-', ord('='): '_', ord('/'): '~'}
    )
    return websafe_b64


def generate_cookie(key: str, value: str, max_age: int = None, path: str = None) -> str:
    cookie = cookies.Morsel()
    cookie.set(
        key=key,
        val=value,
        coded_val=value,
    )
    cookie['secure'] = True
    cookie['httponly'] = True
    if max_age is not None:
        cookie['expires'] = max_age
    if path is not None:
        cookie['path'] = path
    return cookie.OutputString()


def main_url(event):
    return f"https://{os.environ['DOMAIN_NAME']}/"
    # region = os.environ['AWS_REGION']
    # api_id = event['requestContext']['apiId']
    # stage = event['requestContext']['stage']
    # return f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage}/"


def url_origin(url: str) -> str:
    parts = url.split('/')
    return '/'.join(parts[0:3])
