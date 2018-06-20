import jwt.algorithms
import rsa
from jwt.utils import base64url_decode


class RsaAlgorithm(jwt.algorithms.Algorithm):
    SHA256 = 'SHA-256'
    SHA384 = 'SHA-384'
    SHA512 = 'SHA-512'

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_key(self, key):
        return key

    def sign(self, msg, key):
        return rsa.sign(msg, key, self.hash_alg)

    def verify(self, msg, key, sig):
        return rsa.verify(msg, sig, key)

    @staticmethod
    def to_jwk(key_obj):
        raise NotImplementedError()

    @staticmethod
    def from_jwk(jwk):
        n = int.from_bytes(base64url_decode(jwk['n']), byteorder='big', signed=False)
        e = int.from_bytes(base64url_decode(jwk['e']), byteorder='big', signed=False)
        return rsa.PublicKey(n, e)
