from cryptoserve import CryptoServe
from cryptoserve.client import AuthorizationError

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

try:
    crypto.encrypt_string("blood type: A+", context="health-data")
except AuthorizationError as e:
    print(e)
