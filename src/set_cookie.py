"""
Lambda function to issue CloudFront cookies granting access.

Required GET-parameters:
  - token: JWT containing the autorization of the user
  - domain: domain to create cookie for. The domain must be listed in the JWT,
            otherwise, the request is denied (400, bad request)

Note that this Lambda needs to be called on the correct domain in order for the
browser to actually set the cookie on the corresponding domain.
"""

import functools
import json
import os
import time
import typing

import attr
import boto3
import jwt
import rsa
import structlog

from utils import aws_web_safe_base64_encode, get_jwt_secret, generate_case_variants, generate_cookie, \
    VRT_AUTH_ACCESS_COOKIE_NAME

structlog.configure(processors=[structlog.processors.JSONRenderer()])


@attr.s(slots=True, auto_attribs=True)
class SetCookieRequest:
    raw_token: str
    domain: str
    expire: int
    return_to: str


def validate_request(event: dict) -> SetCookieRequest:
    raw_token = event['queryStringParameters']['token']
    policy = jwt.decode(
        raw_token,
        get_jwt_secret(),
        algorithms=['HS256']
    )

    expire = int(policy['exp'])
    # 'exp' is already checked by jwt.decode to be later than now

    domain = event['queryStringParameters']['domain']
    if domain not in policy['domains']:
        raise ValueError('Domain not listed')

    return_to = event['queryStringParameters'].get('return_to', None)

    return SetCookieRequest(
        raw_token=raw_token,
        domain=domain,
        expire=expire,
        return_to=return_to,
    )


def generate_cookie_headers(request: SetCookieRequest) -> typing.List[str]:
    expire_in = int(request.expire - time.time())

    return [
        generate_cookie(VRT_AUTH_ACCESS_COOKIE_NAME, request.raw_token,
                        max_age=expire_in, path='/'),
    ]


def handler(event, context) -> dict:
    try:
        request = validate_request(event)
        structlog.get_logger().log("Valid request", request=request)
    except (KeyError, jwt.InvalidTokenError) as e:
        structlog.get_logger().log("Invalid request", exception=e)
        return {
            'statusCode': 400,
            'body': 'bad request',
        }
    except ValueError as e:
        structlog.get_logger().log("Invalid request: domain missing", exception=e)
        return {
            'statusCode': 400,
            'body': 'You do not have access to this domain.',
        }

    cookies = generate_cookie_headers(request)

    set_cookies_headers = {
        # TODO: fix this
        # This is a workaround for API Gateway
        # API gateway does not support multiple headers with the same name,
        # such as needed to set multiple cookies
        # Luckily, API Gateway also treats header names as case sensitive,
        # while the browser interprets them as case-insensitive (as they should)
        k: v
        for k, v in zip(
            generate_case_variants('Set-Cookie'),
            cookies
        )
    }

    if request.return_to is not None:
        return {
            'statusCode': 302,
            'headers': {
                'Location': request.return_to,
                'Content-Type': 'text/plain',
                **set_cookies_headers,
            },
            'body': 'Redirecting...'
        }

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain',
            **set_cookies_headers,
        },
        'body': f"Toegang verleend tot: {request.domain}\n"
                f"Geldig tot {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime(request.expire))} "
                f"({request.expire})\n",
    }
