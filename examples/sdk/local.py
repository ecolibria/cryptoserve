from cryptoserve import CryptoServe

crypto = CryptoServe.local(password="test-only-password")

token = crypto.encrypt_string("alex.chen@example.com", context="user-pii")
print(crypto.decrypt_string(token, context="user-pii"))
