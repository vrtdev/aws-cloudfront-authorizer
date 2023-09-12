import time
from urllib.parse import urlsplit, urlunsplit, urlencode

import jwt
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()

from utils import get_config, bad_request, get_access_token_jwt_secret, redirect_to_cognito, NotLoggedIn, BadRequest, \
    InternalServerError, internal_server_error, get_refresh_token, get_state_jwt_secret, is_allowed_domain, \
    access_token_from_refresh_token

@logger.inject_lambda_context
def handler(event, context: LambdaContext) -> dict:
    request_ip = event['requestContext']['identity']['sourceIp']
    logger.append_keys(request_id=context.aws_request_id, request_ip=request_ip)
    try:
        redirect_uri = event['queryStringParameters']['redirect_uri']
    except KeyError:
        return bad_request('', "No redirect_uri parameter found")

    redirect_uri_comp = urlsplit(redirect_uri)

    try:
        refresh_token = get_refresh_token(event)
    except NotLoggedIn:
        state = {
            'action': 'authorize',
            'redirect_uri': redirect_uri,
        }
        raw_state = jwt.encode(
            state,
            get_state_jwt_secret(),
            algorithm='HS256',
        )
        return redirect_to_cognito(state=raw_state)
    except BadRequest as e:
        return bad_request('', e)
    except InternalServerError as e:
        return internal_server_error('', e)

    # Is this domain allowed?
    if not is_allowed_domain(redirect_uri_comp.netloc):
        logger.error(f"{redirect_uri} is not an allowed domain")
        return bad_request('', f"{redirect_uri} is not an allowed domain")

    if 'domains' in refresh_token:  # delegated token with domain restrictions
        if redirect_uri_comp.netloc not in refresh_token['domains']:
            logger.error(f"{redirect_uri} is not an allowed domain for this refresh token")
            return bad_request('', f"{redirect_uri} is not an allowed domain for this refresh token")

    try:
        access_token = access_token_from_refresh_token(
            refresh_token,
            redirect_uri_comp.netloc
        )
    except BadRequest as e:
        return bad_request('', e)

    logger.info(f"Redirecting to {redirect_uri} with access token.")
    return {
        'statusCode': 302,
        'headers': {
            'Content-Type': 'text/plain',
            'Location': urlunsplit((
                'https',
                redirect_uri_comp.netloc,
                get_config().set_cookie_path,
                urlencode({  # query
                    'access_token': access_token,  # Key must match with λ@E's expectations
                    'redirect_uri': redirect_uri,  # Key must match with λ@E's expectations
                }),
                '',  # fragment
            )),
        },
        'body': 'Redirecting...',
    }
