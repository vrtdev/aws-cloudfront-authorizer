"""
Lambda function to generate the domain list (in JSON).

It will try to read the domain list from S3, but render a default list if that
fails.
"""
import json
import os

import botocore.exceptions
import botocore
import structlog

from utils import validate_login_cookie, NotLoggedInError, get_domains, DOMAIN_KEY


structlog.configure(processors=[structlog.processors.JSONRenderer()])


def handler(event, context):
    del context  # unused

    try:
        validate_login_cookie(event)  # may raise

        domains = get_domains()

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/json',
            },
            'body': json.dumps(domains),
        }

    except NotLoggedInError:
        return {
            'statusCode': 403,
            'headers': {
                'Content-Type': 'text/plain',
            },
            'body': 'Not logged in',
        }
