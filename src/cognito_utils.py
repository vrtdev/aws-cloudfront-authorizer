import functools
from binascii import a2b_base64

import jwt
import requests

# Use pure python implementation for crypto
from jwt_rsa_algo import RsaAlgorithm

try:
    jwt.register_algorithm('RS256', RsaAlgorithm(RsaAlgorithm.SHA256))
except ValueError:
    pass  # Assume already registered


@functools.lru_cache(maxsize=1)
def get_jwt_keys(region: str, user_pool_id: str) -> dict:
    keys = requests.get(f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json")
    return keys.json()


def import_jwk(jwk: dict):
    return RsaAlgorithm.from_jwk(jwk)


def validate_cognito_id_token(
        token: str,
        region: str,
        user_pool_id: str,
        client_id: str,
) -> dict:
    header = jwt.get_unverified_header(token)
    keys = get_jwt_keys(region, user_pool_id)

    # convert to {kid: key} map, instead of [{kid: kid, ...}, ...] list
    keys = {
        key['kid']: key
        for key in keys['keys']
    }

    key = keys[header['kid']]  # may raise

    public_key = import_jwk(key)
    token = jwt.decode(
        token,
        key=public_key,
        algorithms=['RS256'],
        audience=client_id,
    )
    return token
