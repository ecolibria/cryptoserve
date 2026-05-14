"""Clean app — no crypto, no secrets. Used as the benign release-smoke fixture."""
from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health():
    return {"ok": True}
