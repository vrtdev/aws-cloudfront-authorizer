from datetime import datetime
import json
import os
import sys
import traceback
import typing
from http import cookies
from urllib.parse import urlencode

import boto3
import jwt
import structlog

DOMAIN_KEY = 'domains.json'
CONFIG_KEY = 'config.json'


def cache_with_maxage(
        maybe_func=None,
        default_max_age: int = 60,
):
    """
    Decorator to make a function reuse previous return values up to a certain
    amount of time in the future.

    This is similar to functools.lru_cache, with the following differences:
    * This decorator ignores all arguments!!!
    * An additional (optional) keyword argument is added: `max_age`.
      If it is specified (and not None), it signifies the maximum age (in
      seconds) of cache to use.
    """
    class CachedFunction:
        def __init__(self, func):
            self._func = func
            self._default_max_age = default_max_age
            self._cache_timestamp = None
            self._cache = None

        def __call__(self, *args, **kwargs):
            max_age = kwargs.get('max_age')
            if max_age is None:
                max_age = self._default_max_age
            try:
                del kwargs['max_age']
            except KeyError:
                pass

            now = datetime.utcnow().timestamp()
            min_timestamp = now - max_age

            if self._cache_timestamp is None or \
                    self._cache_timestamp < min_timestamp:
                self._cache = self._func(*args, **kwargs)
                self._cache_timestamp = now

            return self._cache

        def clear_cache(self):
            self._cache_timestamp = None
            self._cache = None

    # maybe_cls's type depends on the usage of the decorator.  It's the function
    # if it's used as `@decorator` but ``None`` if used as `@decorator()`.
    if maybe_func is None:
        return CachedFunction
    else:
        return CachedFunction(maybe_func)


class Config:
    def __init__(self):
        # default settings. Keep in sync with λ@E-code!
        self.parameter_store_region = 'eu-west-1'
        self.parameter_store_parameter_name = '/authorizer/jwt-secret'

        self.set_cookie_path = '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220/set-cookie'

        self.cookie_name_refresh_token = 'refresh_token'
        self.domain_table = "domains"
        self.group_table = "groups"

    def update(self, settings_dict: dict):
        for attr in vars(self).keys():
            if attr in settings_dict:
                setattr(self, attr, settings_dict[attr])


@cache_with_maxage(default_max_age=60)
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


dynamodb_client = boto3.client('dynamodb')


def is_allowed_domain(domain) -> bool:
    table_entry = dynamodb_client.get_item(
        TableName=get_config().domain_table,
        Key={
            "domain": {"S": domain},
        },
    )
    return table_entry.get('Item', {}).get('domain', {}).get('S') == domain


@cache_with_maxage(default_max_age=60)
def get_jwt_secret() -> str:
    # Don't do this at the module level
    # That would make running tests with Mocked SSM much harder
    boto_client = boto3.client('ssm', region_name=get_config().parameter_store_region)
    _jwt_secret = boto_client.get_parameter(
        Name=get_config().parameter_store_parameter_name,
        WithDecryption=True,
    )
    return _jwt_secret['Parameter']['Value']


def get_access_token_jwt_secret() -> str:
    # Must match with λ@E-code
    return get_jwt_secret()


def get_refresh_token_jwt_secret() -> str:
    return get_jwt_secret() + 'rt'


def get_state_jwt_secret() -> str:
    return get_jwt_secret() + 'st'


def get_grant_jwt_secret() -> str:
    return get_jwt_secret() + 'gr'


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


def bad_request(public_details: str = '', private_details=None) -> dict:
    structlog.get_logger().msg(
        "Rendering Bad request",
        public_details=public_details,
        private_details=private_details,
    )
    return {
        'statusCode': 400,
        'headers': {
            'Content-Type': 'text/plain',
        },
        'body': f"Bad request\n{public_details}",
    }


def internal_server_error(public_details: str = '', private_details=None) -> dict:
    structlog.get_logger().msg(
        "Rendering Internal Server Error",
        public_details=public_details,
        private_details=private_details,
    )
    return {
        'statusCode': 500,
        'headers': {
            'Content-Type': 'text/plain',
        },
        'body': f"Internal Server Error\n{public_details}",
    }


def cognito_url(state: str = '') -> str:
    region = os.environ['AWS_REGION']
    domain_prefix = os.environ['COGNITO_DOMAIN_PREFIX']
    client_id = os.environ['COGNITO_CLIENT_ID']
    redirect_uri = f"https://{os.environ['DOMAIN_NAME']}/authenticate"

    location = f"https://{domain_prefix}.auth.{region}.amazoncognito.com/authorize?" + \
           urlencode({
               'identity_provider': os.environ['COGNITO_ADFS_IDP_NAME'],
               'response_type': 'code',
               'client_id': client_id,
               'redirect_uri': redirect_uri,
               'scope': 'openid',
               'state': state,
           })
    return location


def redirect_to_cognito(state: str = '') -> dict:
    """
    Issue a redirect to Cognito.
    """
    location = cognito_url(state)

    structlog.get_logger().msg("Rendering Redirect to Cognito", state=state, location=location)
    return {
        'statusCode': 302,
        'headers': {
            'Location': location,
            'Content-Type': 'text/html'
        },
        'body': f"""\
            <html>
             <head>
              <title>Redirect</title>
             </head>
             <body>
              <p>Redirecting to <a href="{location}">{location}</a></p>
             </body>
            </html>
            """,
    }


class NotLoggedIn(Exception): pass
class BadRequest(Exception): pass
class InternalServerError(Exception): pass

def get_refresh_token(event) -> dict:
    """
    Extract the refresh_token from the Cookie:-header
    :return: the refresh_token payload
    :raises: NotLoggedIn, BadRequest, InternalServerError
    """
    headers = canonicalize_headers(event['headers'])

    try:
        request_cookies = cookies.BaseCookie(headers['cookie'][0])
        raw_refresh_token = request_cookies[get_config().cookie_name_refresh_token].value
    except (KeyError, IndexError):
        structlog.get_logger().log("No refresh_token cookie found")
        raise NotLoggedIn()

    try:
        refresh_token = jwt.decode(  # may raise
            raw_refresh_token,
            key=get_refresh_token_jwt_secret(),
            algorithms=['HS256'],
            verify=True,
        )
        structlog.get_logger().log("Valid refresh_token found", jwt=refresh_token)
    except jwt.ExpiredSignatureError:
        structlog.get_logger().log("Expired token")
        raise NotLoggedIn()
    except jwt.InvalidTokenError:
        structlog.get_logger().log("Invalid token")
        raise BadRequest("Could not decode token")

    return refresh_token
