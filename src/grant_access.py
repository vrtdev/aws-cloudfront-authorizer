"""
Lambda function to generate a HTML page with <iframes>, one for each domain.

This lambda will "duplicate" a single JWT token to multiple domains: It will
render an HTML-page with <iframe>'s, one for each domain listed in the JWT.
"""
import json
import os

import jwt
import attr
import structlog

from utils import get_jwt_secret, generate_cookie, VRT_AUTH_ACCESS_COOKIE_NAME


structlog.configure(processors=[structlog.processors.JSONRenderer()])


@attr.s(slots=True, auto_attribs=True)
class GrantAccessRequest:
    token: dict
    raw_token: str
    domains: set


def validate_request(event: dict) -> GrantAccessRequest:
    raw_token = event['queryStringParameters']['token']
    policy = jwt.decode(
        raw_token,
        get_jwt_secret(),
        algorithms=['HS256']
    )
    structlog.get_logger().log("Decoded token", jwt=policy)

    return GrantAccessRequest(
        token=policy,
        raw_token=raw_token,
        domains=set(policy['domains'])
    )


def handler(event, context) -> dict:
    try:
        request = validate_request(event)
    except (KeyError, jwt.InvalidTokenError) as e:
        structlog.get_logger().log("Invalid request", exception=e)
        return {
            'statusCode': 400,
            'body': 'bad request',
        }

    with open(os.path.join(os.path.dirname(__file__), 'grant_access.html')) as f:
        html = f.read()
        html = html.replace('{{{domains}}}', json.dumps(list(request.domains)))\
                   .replace('{{{path}}}', json.dumps(os.environ['MAGIC_PATH'] + '/set-cookie')) \
                   .replace('{{{token}}}', json.dumps(request.raw_token))
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Set-Cookie': generate_cookie(
                    VRT_AUTH_ACCESS_COOKIE_NAME,
                    request.raw_token,
                    int(request.token['exp']),
                ),
            },
            'body': html,
        }
