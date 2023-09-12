import json
import os
import re
import time
import urllib.parse

import jwt

from utils import redirect_to_cognito, get_refresh_token, NotLoggedIn, BadRequest, \
    bad_request, InternalServerError, internal_server_error, \
    get_grant_jwt_secret, get_state_jwt_secret, get_config, is_allowed_domain, dynamodb_client, get_domains
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()

@logger.inject_lambda_context
def handler(event, context: LambdaContext) -> dict:
    request_ip = event['requestContext']['identity']['sourceIp']
    logger.append_keys(request_id=context.aws_request_id, request_ip=request_ip)

    try:
        refresh_token = get_refresh_token(event)
    except NotLoggedIn:
        state = {
            'action': 'delegate',
        }
        raw_state = jwt.encode(
            state,
            get_state_jwt_secret(),
            algorithm='HS256',
        )
        return redirect_to_cognito(state=raw_state)
    except BadRequest as e:
        return bad_request('', e)
    except InternalServerError as e:
        return internal_server_error('', e)

    if event['httpMethod'] == 'GET':
        logger.info("Rendering index HTML")

        if 'domains' in refresh_token:
            # User wants to further narrow his access
            domains = refresh_token['domains']
            groups = {}
        else:
            domains = get_domains()

            groups = {}
            scan_paginator = dynamodb_client.get_paginator('scan')
            response_iterator = scan_paginator.paginate(
                TableName=get_config().group_table,
            )
            for page in response_iterator:
                for group_entry in page['Items']:
                    try:
                        groups[group_entry['group']['S']] = group_entry['domains']['SS']
                    except KeyError as e:
                        logger.exception("Invalid group in DynamoDB: " + repr(group_entry))
                        pass

        with open(os.path.join(os.path.dirname(__file__), 'delegate.html')) as f:
            html = f.read()
            html = html.replace('{{{domains}}}', json.dumps(domains)) \
                       .replace('{{{groups}}}', json.dumps(groups)) \
                       .replace('{{{use_grant_url}}}', json.dumps(f"https://{os.environ['DOMAIN_NAME']}/use_grant?grant="))


            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/html',
                },
                'body': html,
            }

    elif event['httpMethod'] == 'POST':
        logger.info({"message": "Validating POST request", "body": event['body']})
        values = urllib.parse.parse_qs(event['body'], strict_parsing=True)
        logger.info({"message": "Decoded body", "body": values})

        try:
            exp = int(values['exp'][0])
            del values['exp']

            subject = values['subject'][0]
            assert len(subject) > 0
            del values['subject']
        except (KeyError, AssertionError):
            return bad_request('mandatory fields not present')

        if exp > refresh_token['exp']:
            return bad_request('expiration too long')

        domains = set(values.keys())
        for domain in domains:
            if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
                return bad_request('', f"`{domain}` does not look like a domain name")

            if not is_allowed_domain(domain):
                return bad_request('', 'Unknown domain in request')

        if 'domains' in refresh_token:
            if not domains.issubset(refresh_token['domains']):
                return bad_request('', 'domain requested outside refresh_token')

        delegate_token = {
            'iat': int(time.time()),
            'exp': exp,
            'domains': list(domains),
            'azp': refresh_token['azp'],  # Authorized Party
            'sub': refresh_token.get('sub', []) + [subject],  # subject
        }
        logger.info({"message": "Issuing JWT", "jwt": delegate_token})
        raw_delegate_token = jwt.encode(
            delegate_token,
            get_grant_jwt_secret(),
            algorithm='HS256',
        )

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/plain',
            },
            'body': raw_delegate_token,
        }
        # Token can be passed to
        # https://authorizer/use_grant?grant=<token>
