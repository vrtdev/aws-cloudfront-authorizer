import json
import time
from urllib.parse import urlsplit, urlunsplit, urlencode

import jwt
import structlog

from utils import get_config, bad_request, get_access_token_jwt_secret, redirect_to_cognito, NotLoggedIn, BadRequest, \
    InternalServerError, internal_server_error, get_refresh_token, get_state_jwt_secret, is_allowed_domain, get_domains

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

    access_token = refresh_token  # Copy azp, exp and everything else (sub, if present)
    if 'exp' not in access_token or \
            'azp' not in access_token:
        return bad_request('', 'no exp or azp in token')
    access_token['iat'] = int(time.time())

    access_tokens = {}
    for domain in domains:
        access_token_for_domain = access_token.copy()
        access_token_for_domain['domains'] = [domain]

        raw_access_token = jwt.encode(
            access_token_for_domain,
            get_access_token_jwt_secret(),
            algorithm='HS256',
        ).decode('ascii')

        access_tokens[domain] = raw_access_token

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
        },
        'body': json.dumps(access_tokens),
    }
