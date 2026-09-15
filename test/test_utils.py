import time
from dataclasses import dataclass


def gen_refresh_token(domain: str | None, exp_in: int = 5):
    now = int(time.time())
    token = {
        'iat': now,
        'exp': now + exp_in,
        'azp': 'test',
    }
    if domain is not None:
        token['domains'] = [domain]
    return token


@dataclass
class LambdaContext:
    function_name: str = "test"
    memory_limit_in_mb: int = 128
    invoked_function_arn: str = "arn:aws:lambda:eu-west-1:809313241:function:test"
    aws_request_id: str = "52fdfc07-2182-154f-163f-5f0f9a621d72"
