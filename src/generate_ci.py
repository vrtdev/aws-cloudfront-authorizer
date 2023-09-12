import json
import re
import time

import jwt

from utils import get_access_token_jwt_secret, bad_request, is_allowed_domain
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()

@logger.inject_lambda_context
def handler(event, context: LambdaContext) -> dict:
    request_ip = event['requestContext']['identity']['sourceIp']
    logger.append_keys(request_id=context.aws_request_id, request_ip=request_ip)
    assert event['httpMethod'] == 'POST'

    logger.info({"message": "Processing POST request", "body": event})
    caller = event['requestContext']['identity']['caller']
    values = json.loads(event['body'])

    try:
        exp_in = int(values['exp_in'])

        subject = values['subject']
        assert len(subject) > 0
    except (KeyError, AssertionError):
        return bad_request('mandatory fields not present')

    if exp_in > (60 * 60 * 6):
        return bad_request('expiration too long (max 6 hours)')

    domains = set(values['domains'])
    for domain in domains:
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return bad_request('', f"`{domain}` does not look like a domain name")

        if not is_allowed_domain(domain):
            return bad_request('', 'Unknown domain in request')

    now = int(time.time())
    ci_token = {
        'iat': now,
        'exp': now + exp_in,
        'azp': caller,
        'domains': list(domains),
        'sub': subject,
    }
    logger.info({"message": "Issuing JWT", "jwt": ci_token})
    raw_ci_token = jwt.encode(
        ci_token,
        get_access_token_jwt_secret(),
        algorithm='HS256',
    )

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain',
        },
        'body': raw_ci_token,
    }
