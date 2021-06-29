import json
import os
import time

import jwt

from utils import bad_request, get_grant_jwt_secret, generate_cookie, get_config, get_refresh_token_jwt_secret


def handler(event, context) -> dict:
    del context  # unused

    try:
        raw_grant = event['queryStringParameters']['grant']
    except (TypeError, KeyError):
        return bad_request('', 'missing required parameter')

    try:
        grant = jwt.decode(
            raw_grant,
            get_grant_jwt_secret(),
            algorithms=['HS256'],
        )
        assert 'exp' in grant
        assert 'azp' in grant
        assert 'sub' in grant
        assert 'domains' in grant
    except (jwt.InvalidTokenError, AssertionError):
        return bad_request('', 'invalid grant token')

    refresh_token = grant  # We need to re-sign this with the refresh_token key
    raw_refresh_token = jwt.encode(
        refresh_token,
        get_refresh_token_jwt_secret(),
        algorithm='HS256'
    )

    with open(os.path.join(os.path.dirname(__file__), 'use_grant.html')) as f:
        html = f.read()
        html = html.replace('{{{domains}}}', json.dumps(list(grant['domains'])))\
                   .replace('{{{authorize_url}}}', json.dumps(f"https://{os.environ['DOMAIN_NAME']}/authorize"))

        now = time.time()
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Set-Cookie': generate_cookie(
                    get_config().cookie_name_refresh_token,
                    raw_refresh_token,
                    max_age=int(refresh_token['exp']-now),
                ),
                'Referrer-Policy': 'no-referrer',  # Prevent grant-token from leaking
            },
            'body': html,
        }
