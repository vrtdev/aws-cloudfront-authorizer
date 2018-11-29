import base64
import functools
import json
import os
import sys
import traceback
import typing
from http import cookies

import boto3
import jwt
import structlog

DOMAIN_KEY = 'domains.json'
CONFIG_KEY = 'config.json'


class Config:
    def __init__(self):
        # default settings
        self.verify_access_url = 'https://authorizer.example.org/verify_access'
        self.cookie_name = 'authorizer_access'
        self.login_cookie_name = 'authorizer_login'
        self.parameter_store_region = 'eu-west-1'
        self.parameter_store_parameter_name = '/authorizer/jwt-secret'

    def update(self, settings_dict: dict):
        for attr in vars(self).keys():
            if attr in settings_dict:
                setattr(self, attr, settings_dict[attr])


def get_config() -> Config:
    c = Config()
    try:
        bucket = os.environ.get('CONFIG_BUCKET', "<None>")
        s3_client = boto3.client('s3')
        response = s3_client.get_object(
            Bucket=bucket,
            Key=CONFIG_KEY,
        )
        body = response['Body'].read()
        config = json.loads(body)
        c.update(config)
    except Exception as e:
        print(f"s3.GetObject(Bucket={bucket}, Key={CONFIG_KEY}) failed, continuing with defaults:")
        traceback.print_exception(type(e), e, e.__traceback__, file=sys.stdout)
    return c


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
    """
    HTTP headers are case-insensitive. Join equivalent headers together.
    """
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
    """
    Generates strings based on header_name by varying the case of the letters.

    e.g. "Set-Cookie" -> ["Set-Cookie", "Set-CookiE", "Set-CookIe", ...]
    """
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
        login_token = request_cookies[get_config().login_cookie_name].value

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


def generate_cookie(key: str, value: str, max_age: int = None, path: str = None) -> str:
    """
    Generate the string usable in a Set-Cookie:-header.
    """
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
    del event  # unused
    return f"https://{os.environ['DOMAIN_NAME']}/"
    # region = os.environ['AWS_REGION']
    # api_id = event['requestContext']['apiId']
    # stage = event['requestContext']['stage']
    # return f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage}/"


def url_origin(url: str) -> str:
    """
    Return the protocol & domain-name (without path)
    """
    parts = url.split('/')
    return '/'.join(parts[0:3])


def get_domains():
    try:
        s3_client = boto3.client('s3')
        response = s3_client.get_object(
            Bucket=os.environ['CONFIG_BUCKET'],
            Key=DOMAIN_KEY,
        )
        body = response['Body'].read()
        domains = json.loads(body)
    except Exception as e:
        structlog.get_logger().msg("S3.GetObject() failed, rendering default domain list", exception=e)
        domains = [
            "stag.example.org",
            "images-stag.example.org",
            f"<put a JSON array at s3://{os.environ['CONFIG_BUCKET']}/{DOMAIN_KEY} to change this list>"
        ]
    return domains
