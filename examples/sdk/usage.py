from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

for usage in ["at_rest", "in_use", "streaming"]:
    token = crypto.encrypt(b"4242 4242 4242 4242", context="payment-data", usage=usage)
    print(usage, crypto.decrypt(token, context="payment-data"))
