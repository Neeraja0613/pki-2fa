from app.crypto_utils import decrypt_seed
from app.totp_utils import generate_totp
import datetime

# Path to your encrypted seed file
ENCRYPTED_SEED_FILE = "encrypted_seed.bin"

# Path to log file
LOG_FILE = "data/totp_log.txt"

def log_totp():
    # Read the encrypted seed
    with open(ENCRYPTED_SEED_FILE, "rb") as f:
        encrypted = f.read()

    # Decrypt the seed
    seed_hex = decrypt_seed(encrypted)

    # Generate TOTP
    current_totp = generate_totp(seed_hex)

    # Log TOTP with timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - TOTP: {current_totp}\n"

    # Make sure the data folder exists
    import os
    os.makedirs("data", exist_ok=True)

    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)

    print(f"TOTP logged: {current_totp}")

if __name__ == "__main__":
    log_totp()
