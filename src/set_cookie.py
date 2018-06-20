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

from utils import aws_web_safe_base64_encode, get_jwt_secret, generate_case_variants, generate_cookie

structlog.configure(processors=[structlog.processors.JSONRenderer()])


def generate_policy(domain: str, expire: int) -> dict:
    policy = {
        'Statement': [
            {
                'Resource': f"https://{domain}/*",
                'Condition': {
                    'DateLessThan': {'AWS:EpochTime': expire},
                }
            }
        ]
    }
    return policy


@functools.lru_cache(maxsize=1)
def get_key_id() -> str:
    # Don't do this at the module level
    # That would make running tests with Mocked SSM much harder
    key_id = boto3.client('ssm').get_parameter(
        Name=os.environ['KEY_ID_PARAMETER_NAME'],
    )
    key_id = key_id['Parameter']['Value']
    return key_id


@functools.lru_cache(maxsize=1)
def get_private_key() -> rsa.PrivateKey:
    # Don't do this at the module level
    # That would make running tests with Mocked SSM much harder
    _private_key = boto3.client('ssm').get_parameter(
        Name=os.environ['PRIVATE_KEY_PARAMETER_NAME'],
        WithDecryption=True,
    )
    _private_key = rsa.PrivateKey.load_pkcs1(_private_key['Parameter']['Value'])
    return _private_key


@attr.s(slots=True, auto_attribs=True)
class SetCookieRequest:
    domain: str
    expire: int
    return_to: str


def validate_request(event: dict) -> SetCookieRequest:
    policy = jwt.decode(
        event['queryStringParameters']['token'],
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
        domain=domain,
        expire=expire,
        return_to=return_to,
    )


def generate_cookie_headers(request: SetCookieRequest) -> typing.List[str]:
    policy = generate_policy(request.domain, request.expire)
    structlog.get_logger().log("Generating signed cookies", policy=policy)

    policy_b = json.dumps(policy, indent=None, separators=(',', ':')).encode('utf-8')

    signature_b = rsa.sign(policy_b, get_private_key(), 'SHA-1')
    # TODO: rsa.sign() is really slow on Lambda (3 seconds per call) => optimize this by changing to Cryptography
    # once we have the infrastructure to build dynamic loadable objects for Lambda

    expire_in = int(request.expire - time.time())

    return [
        generate_cookie('CloudFront-Key-Pair-Id', get_key_id(),
                        max_age=expire_in, path='/'),
        generate_cookie('CloudFront-Policy', aws_web_safe_base64_encode(policy_b),
                        max_age=expire_in, path='/'),
        generate_cookie('CloudFront-Signature', aws_web_safe_base64_encode(signature_b),
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
