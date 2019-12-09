import json
import time
from urllib.parse import urlsplit, urlunsplit, urlencode

import jwt
import structlog

from utils import get_config, bad_request, get_access_token_jwt_secret, redirect_to_cognito, NotLoggedIn, BadRequest, \
    InternalServerError, internal_server_error, get_refresh_token, get_state_jwt_secret, is_allowed_domain, get_domains, \
    access_token_from_refresh_token

structlog.configure(processors=[structlog.processors.JSONRenderer()])


def handler(event, context) -> dict:
    del context  # unused

    try:
        refresh_token = get_refresh_token(event)
    except NotLoggedIn:
        return {
            'statusCode': 401,
            'body': "Not logged in",
        }
    except BadRequest as e:
        return bad_request('', e)
    except InternalServerError as e:
        return internal_server_error('', e)

    if 'domains' in refresh_token:  # delegated token with domain restrictions
        domains = refresh_token['domains']
    else:
        domains = get_domains()

    access_tokens = {}
    try:
        for domain in domains:
            access_tokens[domain] = access_token_from_refresh_token(
                refresh_token,
                domain,
            )
    except BadRequest as e:
        return bad_request('', e)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
        },
        'body': json.dumps(access_tokens),
    }
