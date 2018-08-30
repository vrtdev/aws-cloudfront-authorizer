import os
from http import cookies
from urllib.parse import urlsplit, urlunsplit, urlencode

import jwt
import structlog
import attr

from utils import canonicalize_headers, AUTH_ACCESS_COOKIE_NAME, get_jwt_secret


structlog.configure(processors=[structlog.processors.JSONRenderer()])


@attr.s(slots=True, auto_attribs=True)
class VerifyAccessRequest:
    raw_token: str
    access_token: dict
    return_to: str


def validate_request(event: dict) -> VerifyAccessRequest:
    headers = canonicalize_headers(event['headers'])
    request_cookies = cookies.BaseCookie(headers['cookie'][0])
    access_token = request_cookies[AUTH_ACCESS_COOKIE_NAME].value

    token = jwt.decode(  # may raise
        access_token,
        key=get_jwt_secret(),
        algoritms=['HS256'],
        verify=True,
    )
    structlog.get_logger().log("Valid access token found", jwt=token)

    return_to = event['queryStringParameters']['return_to']

    return VerifyAccessRequest(
        raw_token=access_token,
        access_token=token,
        return_to=return_to,
    )


def handler(event, context) -> dict:
    try:
        request = validate_request(event)
    except (KeyError, jwt.InvalidTokenError) as e:
        structlog.get_logger().log("Invalid request", exception=e)
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'text/plain',
            },
            'body': 'You do not have access to this site.',
        }

    return_to = urlsplit(request.return_to)

    return {
        'statusCode': 302,
        'headers': {
            'Content-Type': 'text/plain',
            'Location': urlunsplit((
                'https',
                return_to.netloc,
                os.environ['MAGIC_PATH'] + '/set-cookie',
                urlencode({  # query
                    'domain': return_to.netloc,
                    'token': request.raw_token,
                    'return_to': request.return_to,
                }),
                '',  # fragment
            )),
        },
        'body': 'Redirecting...',
    }
