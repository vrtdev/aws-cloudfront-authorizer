import time
import typing


def gen_refresh_token(domain: typing.Optional[str], exp_in: int = 5):
    now = int(time.time())
    token = {
        'iat': now,
        'exp': now + exp_in,
        'azp': 'test',
    }
    if domain is not None:
        token['domains'] = [domain]
    return token