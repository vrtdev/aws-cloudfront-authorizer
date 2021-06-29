import os
import time
import traceback
import urllib.parse

import jwt
import requests
import requests.auth
import structlog

from cognito_utils import validate_cognito_id_token
from utils import bad_request, internal_server_error, get_refresh_token_jwt_secret, get_state_jwt_secret, \
    generate_cookie, get_config

structlog.configure(processors=[structlog.processors.JSONRenderer()])


class InternalServerError(Exception): pass
class BadRequest(Exception): pass


def exchange_cognito_code(event: dict, cognito_code: str) -> dict:
    """
    Validate a Cognito Code and fetch the associated ID-token.
    Returns the identity-token.
    Raises BadRequest (client's fault) or InternalServerError (config or backend issue)
    :raises: BadRequest, InternalServerError
    """
    region = os.environ['AWS_REGION']
    domain_prefix = os.environ['COGNITO_DOMAIN_PREFIX']
    client_id = os.environ['COGNITO_CLIENT_ID']
    client_secret = os.environ['COGNITO_CLIENT_SECRET']
    redirect_uri = f"https://{os.environ['DOMAIN_NAME']}/authenticate"

    endpointurl = f'https://{domain_prefix}.auth.{region}.amazoncognito.com/oauth2/token'

    post_data = {
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'scope': 'openid',
        'redirect_uri': redirect_uri,
        'code': cognito_code,
    }
    structlog.get_logger().msg("Validating Cognito code")
    try:
        token_response = requests.post(
            endpointurl,
            data=post_data,
            auth=requests.auth.HTTPBasicAuth(client_id, client_secret)
        )
    except requests.exceptions.ConnectionError as e:
        structlog.get_logger().msg("Connection error to Cognito", exception=e)
        raise InternalServerError()

    if token_response.status_code != 200:
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

    cognito_token = token_response.json()
    structlog.get_logger().msg("Received Cognito tokens")

    try:
        cognito_id_token = validate_cognito_id_token(
            token=cognito_token['id_token'],
            region=region,
            user_pool_id=os.environ['COGNITO_USER_POOL_ID'],
            client_id=client_id,
        )
    except requests.exceptions.RequestException as e:
        structlog.get_logger().msg("Connection error to Cognito", exception=e)
        raise InternalServerError()
    except jwt.InvalidTokenError as e:
        structlog.get_logger().msg("id_token invalid", exception=e)
        raise InternalServerError()

    structlog.get_logger().msg("Cognito ID token is valid")

    return cognito_id_token


def handler(event, context) -> dict:
    del context  # unused

    try:
        cognito_code = event['queryStringParameters']['code']
        state = event['queryStringParameters']['state']

    except (TypeError, KeyError):
        return bad_request('', 'missing required parameter')

    try:
        state = jwt.decode(
            state,
            get_state_jwt_secret(),
            algorithms=['HS256'],
        )
    except jwt.InvalidTokenError:
        return bad_request('', 'invalid state token')

    try:
        cognito_token = exchange_cognito_code(event, cognito_code)
    except BadRequest:
        return bad_request()
    except InternalServerError:
        return internal_server_error()

    # Issue a token valid for 180 days. This allows the user to issue delegate
    # tokens for up to this time.
    # But set the expiration of the Cookie itself to the validity of the
    # Cognito token.
    # Unless the user actively safeguards his cookie, he will have to
    # re-authenticate with Cognito. If this is malicious intend, the user
    # could delegate the same access to himself, and get the same result.
    now = int(time.time())
    refresh_token = {
        'iat': now,  # Issued AT
        'exp': now + 180*24*60*60,  # EXPire: 180 days, maximum duration of delegated tokens
        'azp': cognito_token['cognito:username'],  # AuthoriZed Party
    }
    raw_refresh_token = jwt.encode(
        refresh_token,
        get_refresh_token_jwt_secret(),
        algorithm='HS256',
    )

    structlog.get_logger().msg("Cognito Code exchanged succesfully, issuing refresh_token",
                               refresh_token=refresh_token)  # Don't log signed token, only payload

    try:
        if state['action'] == 'index':
            location = f"https://{os.environ['DOMAIN_NAME']}/"
        elif state['action'] == 'delegate':
            location = f"https://{os.environ['DOMAIN_NAME']}/delegate"
        elif state['action'] == 'authorize':
            location = f"https://{os.environ['DOMAIN_NAME']}/authorize?" + \
                f"redirect_uri={urllib.parse.quote_plus(state['redirect_uri'])}"
        else:
            raise ValueError(f"Invalid action `{state['action']}`")
    except (KeyError, ValueError) as e:
        structlog.get_logger().msg("state is invalid", exception=e)
        return internal_server_error()

    return {
        'statusCode': 302,
        'headers': {
            'Content-Type': 'text/plain',
            'Location': location,
            'Set-Cookie': generate_cookie(
                get_config().cookie_name_refresh_token,
                raw_refresh_token,
                max_age=int(cognito_token['exp'] - now)
            ),
        },
        'body': 'Redirecting...',
    }
