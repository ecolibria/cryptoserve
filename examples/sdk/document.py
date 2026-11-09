from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

token = crypto.encrypt_json({"email": "alex.chen@example.com", "plan": "team"}, context="user-pii")
print(crypto.decrypt_json(token, context="user-pii"))
