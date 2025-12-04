# app/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
from app.crypto_utils import decrypt_seed, load_private_key
from app.totp_utils import generate_totp, verify_totp

app = FastAPI()

# Path to store decrypted seed
SEED_FILE = "/data/seed.txt"
PRIVATE_KEY_FILE = "student_private.pem"  # Update path if needed

# Request models
class DecryptSeedRequest(BaseModel):
    encrypted_seed: str

class Verify2FARequest(BaseModel):
    code: str

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(request: DecryptSeedRequest):
    try:
        # Load private key
        private_key = load_private_key(PRIVATE_KEY_FILE)
        # Decrypt seed
        seed_hex = decrypt_seed(request.encrypted_seed, private_key)
        # Save to file for persistence
        os.makedirs("/data", exist_ok=True)
        with open(SEED_FILE, "w") as f:
            f.write(seed_hex)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

@app.get("/generate-2fa")
def generate_2fa_endpoint():
    if not os.path.exists(SEED_FILE):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    with open(SEED_FILE, "r") as f:
        seed_hex = f.read().strip()
    code = generate_totp_code(seed_hex)
    # Calculate remaining seconds in current period
    import time
    valid_for = 30 - int(time.time()) % 30
    return {"code": code, "valid_for": valid_for}

@app.post("/verify-2fa")
def verify_2fa_endpoint(request: Verify2FARequest):
    if not request.code:
        raise HTTPException(status_code=400, detail="Missing code")
    if not os.path.exists(SEED_FILE):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    with open(SEED_FILE, "r") as f:
        seed_hex = f.read().strip()
    is_valid = verify_totp_code(seed_hex, request.code)
    return {"valid": is_valid}

# Run with: uvicorn app.main:app --host 0.0.0.0 --port 8080
