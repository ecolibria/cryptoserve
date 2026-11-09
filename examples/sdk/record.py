from cryptoserve import CryptoServe

crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])

user = {"id": 42, "email": "alex.chen@example.com", "card": "4242 4242 4242 4242"}
row = {
    "id": user["id"],
    "email": crypto.encrypt_string(user["email"], context="user-pii"),
    "card": crypto.encrypt_string(user["card"], context="payment-data"),
}
print({column: len(value) if isinstance(value, str) else value for column, value in row.items()})
print(crypto.decrypt_string(row["card"], context="payment-data"))
