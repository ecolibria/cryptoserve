from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

token = crypto.encrypt_string("alex.chen@example.com", context="user-pii")
print(token[:48] + "...")
print(crypto.decrypt_string(token, context="user-pii"))
