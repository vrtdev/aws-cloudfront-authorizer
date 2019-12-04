import json
import os
import time

import jwt

from utils import get_refresh_token, NotLoggedIn, BadRequest, InternalServerError, internal_server_error, cognito_url, \
    get_state_jwt_secret


def handler(event, context) -> dict:
    del context  # unused

    refresh_token_exp = None
    domains = None
    azp = None
    sub = []
    try:
        refresh_token = get_refresh_token(event)

        refresh_token_exp = refresh_token['exp']
        azp = refresh_token['azp']  # Mandatory
        sub = refresh_token.get('sub', [])  # optional

        try:
            domains = refresh_token['domains']
        except KeyError:
            pass
    except (NotLoggedIn, BadRequest):
        pass
    except InternalServerError as e:
        return internal_server_error('Something went wrong parsing the refresh token', e)

    state = {
        'action': 'index',
    }
    raw_state = jwt.encode(
        state,
        get_state_jwt_secret(),
        algorithm='HS256',
    )

    with open(os.path.join(os.path.dirname(__file__), 'index.html')) as f:
        html = f.read()
        html = html.replace('{{{authenticate}}}', cognito_url(raw_state)) \
                   .replace('{{{refresh_token_exp}}}', json.dumps(refresh_token_exp)) \
                   .replace('{{{domains}}}', json.dumps(domains)) \
                   .replace('{{{azp}}}', json.dumps(azp)) \
                   .replace('{{{sub}}}', json.dumps(sub))

        now = time.time()
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
            },
            'body': html,
        }
