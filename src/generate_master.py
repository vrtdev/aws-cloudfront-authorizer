import time

import boto3
import jwt
import structlog

from utils import get_access_token_jwt_secret, get_config, get_domains

def handler(event, context) -> dict:
    # unused
    del event
    del context

    domains = get_domains()
    now = int(time.time())
    master_token = {
        'iat': now,
        'exp': now + (60 * 60 * 25), # 25 hours
        'azp': "authorizer",
        'domains': list(domains),
        'sub': "master token",
    }
    structlog.get_logger().msg("Issuing JWT", jwt=master_token)
    raw_master_token = jwt.encode(
        master_token,
        get_access_token_jwt_secret(),
        algorithm='HS256',
    )

    put_master_parameter(raw_master_token)

    return {
        'statusCode': 200,
    }


def put_master_parameter(token: str) -> None:
    # Don't do this at the module level
    # That would make running tests with Mocked SSM much harder
    boto_client = boto3.client('ssm', region_name=get_config().parameter_store_region)
    boto_client.put_parameter(
        Name=get_config().parameter_store_master_name,
        Overwrite=True,
        Value=token,
    )
