import os
import time
import urllib.parse

import jwt
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

from utils import generate_cookie, get_config, bad_request, get_csrf_jwt_secret, get_raw_refresh_token, NotLoggedIn

logger = Logger()

@logger.inject_lambda_context
def handler(event, context: LambdaContext) -> dict:
    request_ip = event['requestContext']['identity']['sourceIp']
    logger.append_keys(request_id=context.aws_request_id, request_ip=request_ip)

    logger.info({"message": "Processing POST request", "body": event['body']})
    values = urllib.parse.parse_qs(event['body'], strict_parsing=True)
    logger.info({"body": values})

    try:
        csrf = values['CSRF'][0]
        csrf = jwt.decode(
            csrf,
            key=get_csrf_jwt_secret(),
            algorithms=['HS256'],
        )
        now = time.time()
        assert csrf['iat'] >= now - 300

        raw_refresh_token = get_raw_refresh_token(event)
        assert csrf['sub'] == raw_refresh_token

    except KeyError:
        return bad_request('', 'CSRF token missing')
    except jwt.InvalidTokenError:
        return bad_request('', 'CSRF token decode failed')
    except AssertionError as e:
        return bad_request('CSRF token unacceptable, please try again', e)
    except NotLoggedIn:
        pass

    with open(os.path.join(os.path.dirname(__file__), 'logout.html')) as f:
        html = f.read()

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Set-Cookie': generate_cookie(
                    get_config().cookie_name_refresh_token,
                    "",
                    max_age=-1,
                ),
                'Referrer-Policy': 'no-referrer',  # Prevent grant-token from leaking
            },
            'body': html,
        }
