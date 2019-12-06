import os
import time
import urllib.parse

import jwt
import structlog

from utils import generate_cookie, get_config, bad_request, get_csrf_jwt_secret, get_raw_refresh_token, NotLoggedIn

structlog.configure(processors=[structlog.processors.JSONRenderer()])


def handler(event, context) -> dict:
    del context  # unused

    structlog.get_logger().log("Validating POST request", body=event['body'])
    values = urllib.parse.parse_qs(event['body'], strict_parsing=True)
    structlog.get_logger().log("Decoded body", body=values)

    try:
        csrf = values['CSRF'][0]
        csrf = jwt.decode(
            csrf,
            key=get_csrf_jwt_secret(),
            algorithms=['HS256'],
            verify=True,
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
