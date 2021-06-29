from unittest import mock

import jwt
import pytest

from src import cognito_utils


id_token = "eyJraWQiOiJTVUxMd0xFeWthcVpCbHpYQityR0pZY0h6Q1Y2SHZ2ZXhSZk5oZVptZW1BPSIsImFsZyI6IlJTMjU2In0.eyJhd" \
           "F9oYXNoIjoiTWU4NjYzazVNRGhDcGxhRDF4R1hEUSIsInN1YiI6Ijg0NGE0MDEwLTBlYjEtNGY3Yy1hOGM5LTMyYjFmNzZlND" \
           "hhYiIsImF1ZCI6IjIzZW1xbjBibTU4bmVqdXZsOWp1NXVnNTBtIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE1MzA" \
           "1MjgzNDUsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5ldS13ZXN0LTEuYW1hem9uYXdzLmNvbVwvZXUtd2VzdC0xX3Bt" \
           "UjRZSXZWbyIsImNvZ25pdG86dXNlcm5hbWUiOiJhZG1pbiIsImV4cCI6MTUzMDUzMTk0NSwiaWF0IjoxNTMwNTI4MzQ1fQ.Hp" \
           "9DOWSyZhTPTIhnb5999KRvQcHEYEFvzVgVFwM6cFjYJTrHsN-StYxjwAr5nze6jlKa_YJn9WCZzrLswBpoew9GpUUhRmaJzD2" \
           "paEhKTjtrMVcz-KTcnqrq0NRduJQA_5SAfXHtqwTNxPhT7wS9Zu_j0y_DisY9Ik9FNB4wwFGmBqcXyyZ15wnx46WEcqK8uG2l" \
           "XgHAm6OziICLFs0NfRH2YAH9MAeC0bNzu24QffFDTHs3H_0fZCEsgkmtCBV2sFP-WUEt17VVnFndME5YlmSg_YH3y8hGsaOWt" \
           "6b1fNmQbrpg1dSuxejrXkeOEj9dywHirOQ_P6rYSYwDEUho-Q"
jwk = {
    "keys": [
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "SULLwLEykaqZBlzXB+rGJYcHzCV6HvvexRfNheZmemA=",
            "kty": "RSA",
            "n": "wXTc7_RjnttQHKZOX6zYznagj2wmgJjCeyFOvrn0csRdem8CGXMsDXGUUS4JHk0clsfik0tL5aEeCrO_YpzL78AI2u"
                 "iqwtmu3slLOEENce0vNI1SU2WzqxQ9sUKLv0mKWesvF9ukJ8hEN9GYJ2ng6wUtnRlKh8qlIkiBlKogNQiQk21bvk6B"
                 "VX0TWQ_RRlth22zMxdv0VUDNZd8xopy9DSJ9-9jpFidbSY1y24vbeDYewztshsHomAaW2cAzpxmJ12oSs9OgvLROFP"
                 "tbANG7-0netCHeTPaAtXLo_0s-c35gHUziCcxYEM4PR7GZOvX1IUfIvxblG1BNHJAi79cDbw",
            "use": "sig"
        },
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "Uvl7gbkg90A6y9tiPJCHLQiPvahfeS3SbkLJhGm6X9w=",
            "kty": "RSA",
            "n": "uZGdqh7TsN_fvL3hMKrLBa5yyZBAOLM2DVcVTDjCKl7YxHTbAMevOd232Fj3tB4BiAMzKdJHBXBO4imWJ95i3O4Bxv"
                 "Eg5mRA4Gu5CHcM88gNB6eFfPUpXT_XxSmRd5AXT9yfTE6lhFNsfxX5v_yl_qDRHEnST0dJm9xL9hGAbe5ZeKHf3HDY"
                 "D-k1lR5TqceEutzJdpJg-grm6VhXvFF52U9ZmfBkA3yi8D_895WSKbHTfGCCKfP4mdF286jrFifGkxu2EK-lCM0dwv"
                 "4l_JZxFB3ds1hkTs5uog1PHzeoBBwSs1aaC6QT_M_whfVBur1TGKRXq0OHaQkPhYo5KR6SXQ",
            "use": "sig"
        }
    ]
}


def test_jwt_parsing():
    jwt_decode_original = jwt.decode

    def jwt_decode(*args, **kwargs):
        # Don't verify expired tokens
        kwargs['options'] = { "verify_signature": False }
        return jwt_decode_original(*args, **kwargs)

    with mock.patch('src.cognito_utils.get_jwt_keys', return_value=jwk), \
            mock.patch('jwt.decode', side_effect=jwt_decode):
        token = cognito_utils.validate_cognito_id_token(
            token=id_token,
            region='unused because of get_jwt_keys() mock',
            user_pool_id='unused because of get_jwt_keys() mock',
            client_id='unused because of get_jwt_keys() mock',
        )
        assert token['aud'] == '23emqn0bm58nejuvl9ju5ug50m'
        assert token['cognito:username'] == 'admin'


def test_jwt_parsing_expired():
    with mock.patch('src.cognito_utils.get_jwt_keys', return_value=jwk):
        with pytest.raises(jwt.exceptions.ExpiredSignatureError):
            cognito_utils.validate_cognito_id_token(
                token=id_token,
                region='unused because of get_jwt_keys() mock',
                user_pool_id='unused because of get_jwt_keys() mock',
                client_id='unused because of get_jwt_keys() mock',
            )
