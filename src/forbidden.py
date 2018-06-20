import json

from utils import main_url


def handler(event, context):
    with open('forbidden.html') as f:
        html = f.read()
        html = html.replace('{{{auth_url}}}', json.dumps(main_url(event)))
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
            },
            'body': html,
        }
