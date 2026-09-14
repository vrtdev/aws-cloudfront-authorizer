import json

from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

from utils import (
    BadRequest,
    InternalServerError,
    NotLoggedIn,
    access_token_from_refresh_token,
    bad_request,
    get_domains,
    get_refresh_token,
    internal_server_error,
)

logger = Logger()

@logger.inject_lambda_context
def handler(event, context: LambdaContext) -> dict:
    request_ip = event['requestContext']['identity']['sourceIp']
    logger.append_keys(request_id=context.aws_request_id, request_ip=request_ip)

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
