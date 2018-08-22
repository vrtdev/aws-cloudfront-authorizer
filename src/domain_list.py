import json
import os

import botocore.exceptions
import botocore
import structlog

from utils import validate_login_cookie, NotLoggedInError, get_domains

structlog.configure(processors=[structlog.processors.JSONRenderer()])


def handler(event, context):
    try:
        validate_login_cookie(event)  # may raise

        try:
            domains = get_domains()
        except botocore.exceptions.ClientError as e:
            structlog.get_logger().msg("get_domains() failed, rendering default domain list", exception=e)
            domains = [
                "stag.example.org",
                "images-stag.example.org",
                f"<put a JSON array at s3://{os.environ['CONFIG_BUCKET']}/{DOMAIN_KEY} to change this list>"
            ]

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
