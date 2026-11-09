from fastapi import FastAPI
from pydantic import BaseModel
from cryptoserve import CryptoServe

app = FastAPI()
crypto = CryptoServe(app_name="my-app", contexts=["user-pii", "payment-data"])
rows = {}

class User(BaseModel):
    email: str

@app.put("/users/{user_id}")
def save_user(user_id: int, user: User):
    rows[user_id] = crypto.encrypt_string(user.email, context="user-pii")
    return {"stored_characters": len(rows[user_id])}

@app.get("/users/{user_id}")
def read_user(user_id: int):
    return {"email": crypto.decrypt_string(rows[user_id], context="user-pii")}
