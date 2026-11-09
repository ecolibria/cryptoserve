from cryptoserve import CryptoServe
from cryptoserve.client import CryptoServeError

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

email = crypto.encrypt_string("alex.chen@example.com", context="user-pii", associated_data=b"users:42:email")
print(crypto.decrypt_string(email, context="user-pii", associated_data=b"users:42:email"))

try:
    crypto.decrypt_string(email, context="user-pii", associated_data=b"users:43:email")
except CryptoServeError as e:
    print("refused:", e)
