"""
Main website entry point.

We have 3 distinct situation:
 * The user is not logged in: Redirect to Cognito to log in
 * The user is returning from Cognito: Swap the Cognito code for our own Cookie.
                                       The user is now logged in
 * The user is logged in: Return HTML
"""
import os
import time
import traceback
import typing
import urllib.parse

import jwt
import requests
import requests.auth
import structlog

from cognito_utils import validate_cognito_id_token
from utils import VRT_AUTH_LOGIN_COOKIE_NAME, get_jwt_secret, validate_login_cookie, NotLoggedInError, generate_cookie, \
    main_url

structlog.configure(processors=[structlog.processors.JSONRenderer()])


def redirect(event):
    region = os.environ['AWS_REGION']
    domain_prefix = os.environ['COGNITO_DOMAIN_PREFIX']
    client_id = os.environ['COGNITO_CLIENT_ID']

    redirect_uri = main_url(event)

    location = f"https://{domain_prefix}.auth.{region}.amazoncognito.com/login?" + \
               urllib.parse.urlencode({
                   'response_type': 'code',
                   'client_id': client_id,
                   'redirect_uri': redirect_uri,
                   'scope': 'openid',
               })

    structlog.get_logger().msg("Rendering Redirect", location=location)
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


def index_page(extra_headers: typing.Dict[str, str] = None):
    if extra_headers is None:
        extra_headers = {}

    structlog.get_logger().msg("Rendering index HTML")
    with open(os.path.join(os.path.dirname(__file__), 'index.html')) as f:
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                **extra_headers,
            },
            'body': f.read(),
        }


class InternalServerError(Exception):
    pass


class BadRequest(Exception):
    pass


def exchange_cognito_code(event: dict, cognito_code: str) -> dict:
    """
    Validate a Cognito Code for an ID-token.
    Returns the identity-token.
    Raises BadRequest (client's fault) or InternalServerError (config or backend issue)
    :raises: InternalServerError, BadRequest
    """
    region = os.environ['AWS_REGION']
    domain_prefix = os.environ['COGNITO_DOMAIN_PREFIX']
    client_id = os.environ['COGNITO_CLIENT_ID']
    client_secret = os.environ['COGNITO_CLIENT_SECRET']

    endpointurl = f'https://{domain_prefix}.auth.{region}.amazoncognito.com/oauth2/token'

    try:
        post_data = {
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'scope': 'openid',
            'redirect_uri': main_url(event),
            'code': cognito_code,
        }
        structlog.get_logger().msg("Validating Cognito code", **post_data)
        token_response = requests.post(
            endpointurl,
            data=post_data,
            auth=requests.auth.HTTPBasicAuth(client_id, client_secret)
        )
        structlog.get_logger().msg("Cognito reply", reply=token_response)
        token_response.raise_for_status()
        cognito_token = token_response.json()
        structlog.get_logger().msg("Cognito tokens", reply=cognito_token)

        cognito_id_token = validate_cognito_id_token(
            token=cognito_token['id_token'],
            region=region,
            user_pool_id=os.environ['COGNITO_USER_POOL_ID'],
            client_id=client_id,
        )
        structlog.get_logger().msg("Cognito ID token is valid", id_token=cognito_id_token)

        return cognito_id_token

    except requests.exceptions.HTTPError:
        try:
            error_response = token_response.json()
            structlog.get_logger().msg("Cognito error response", reply=error_response)

            if error_response['error'] == 'invalid_grant':
                raise BadRequest(error_response['error'])

            raise InternalServerError(error_response['error'])

        except (BadRequest, InternalServerError):
            raise
        except Exception as e:
            structlog.get_logger().msg(
                "Uncaught error",
                cognito_reply=token_response.text,
                exception=e,
                backtrace=traceback.format_exc()
            )
            raise InternalServerError() from e


def handler(event, context):
    try:
        try:  # Assume user is logged in
            validate_login_cookie(event)
            return index_page()
        except NotLoggedInError as e:
            structlog.get_logger().msg("User not logged in", exception=e)
            # Fall through, try next

        try:  # Assume user is returning from Cognito
            cognito_code = event['queryStringParameters']['code']
            # ^^^ may raise TypeError if queryStringParameters is None, or KeyError when no 'code' is given

            cognito_token = exchange_cognito_code(event, cognito_code)

            jwt_content = {
                'iat': int(time.time()),  # Issued at
                'exp': cognito_token['exp'],  # Expire
                'azp': cognito_token['cognito:username'],  # Authorized party
            }
            vrt_auth_token = jwt.encode(
                jwt_content,
                get_jwt_secret(),
                algorithm='HS256',
            ).decode('ascii')

            structlog.get_logger().msg("Cognito Code exchanged succesfully, issuing JWT", jwt=jwt_content)
            return index_page({
                'Set-Cookie': generate_cookie(VRT_AUTH_LOGIN_COOKIE_NAME, vrt_auth_token),
            })
        except InternalServerError as e:
            structlog.get_logger().msg("Could not validate Cognito code", exception=e)
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'text/plain',
                },
                'body': 'There was an error validating your request.'
            }
        except BadRequest as e:
            structlog.get_logger().msg("Code seems invalid", exception=e)
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'text/plain',
                },
                'body': 'Invalid token.'
            }
        except (TypeError, KeyError):
            structlog.get_logger().msg("No Cognito code provided")
            # Fall through, try next

        # Not logged in, not returning from Cognito
        return redirect(event)

    except Exception as e:
        structlog.get_logger().msg("Uncaught exception", exception=e, backtrace=traceback.format_exc())
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'text/plain',
            },
            'body': 'Internal Server Error\nsee logs for more details',
        }
