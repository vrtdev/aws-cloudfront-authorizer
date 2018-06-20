from utils import validate_login_cookie, NotLoggedInError


def handler(event, context):
    try:
        validate_login_cookie(event)  # may raise

        with open('domains.json') as f:
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/json',
                },
                'body': f.read()
            }

    except NotLoggedInError:
        return {
            'statusCode': 403,
            'headers': {
                'Content-Type': 'text/plain',
            },
            'body': 'Not logged in',
        }
