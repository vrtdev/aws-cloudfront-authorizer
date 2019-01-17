import time
from urllib.parse import urlsplit, urlunsplit, urlencode

import jwt
import structlog

from utils import get_config, bad_request, get_access_token_jwt_secret, redirect_to_cognito, NotLoggedIn, BadRequest, \
    InternalServerError, internal_server_error, get_refresh_token, get_state_jwt_secret, is_allowed_domain

structlog.configure(processors=[structlog.processors.JSONRenderer()])


def handler(event, context) -> dict:
    del context  # unused

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
        return bad_request('', f"{redirect_uri} is not an allowed domain")

    if 'domains' in refresh_token:  # delegated token with domain restrictions
        if redirect_uri_comp.netloc not in refresh_token['domains']:
            return bad_request('', f"{redirect_uri} is not an allowed domain for this refresh token")

    access_token = refresh_token  # Copy azp, exp and everything else (sub, if present)
    if 'exp' not in access_token or \
            'azp' not in access_token:
        return bad_request('', 'no exp or azp in token')
    access_token['iat'] = int(time.time())
    access_token['domains'] = [redirect_uri_comp.netloc]  # Limit scope to single domain

    raw_access_token = jwt.encode(
        access_token,
        get_access_token_jwt_secret(),
        algorithm='HS256',
    ).decode('ascii')

    return {
        'statusCode': 302,
        'headers': {
            'Content-Type': 'text/plain',
            'Location': urlunsplit((
                'https',
                redirect_uri_comp.netloc,
                get_config().set_cookie_path,
                urlencode({  # query
                    'access_token': raw_access_token,  # Key must match with λ@E's expectations
                    'redirect_uri': redirect_uri,  # Key must match with λ@E's expectations
                }),
                '',  # fragment
            )),
        },
        'body': 'Redirecting...',
    }
