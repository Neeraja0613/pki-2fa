import hmac
import hashlib
import struct
import time

def _int_to_bytes(i):
    return struct.pack(">Q", i)

def generate_totp(hex_seed: str, timestep: int = 30, digits: int = 6):
    # Convert hex string to bytes
    key = bytes.fromhex(hex_seed)

    # Current time step (UTC)
    counter = int(time.time() // timestep)

    # HMAC-SHA1
    hmac_hash = hmac.new(key, _int_to_bytes(counter), hashlib.sha1).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = (
        ((hmac_hash[offset] & 0x7F) << 24) |
        ((hmac_hash[offset + 1] & 0xFF) << 16) |
        ((hmac_hash[offset + 2] & 0xFF) << 8) |
        (hmac_hash[offset + 3] & 0xFF)
    )

    otp = code % (10 ** digits)
    return str(otp).zfill(digits)

def verify_totp(hex_seed: str, code: str, timestep: int = 30, digits: int = 6, window: int = 1):
    # Try previous, current, next time window
    key = bytes.fromhex(hex_seed)
    current_counter = int(time.time() // timestep)

    for offset in range(-window, window + 1):
        counter = current_counter + offset
        hmac_hash = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()

        dynamic_offset = hmac_hash[-1] & 0x0F
        calc_code = (
            ((hmac_hash[dynamic_offset] & 0x7F) << 24) |
            ((hmac_hash[dynamic_offset + 1] & 0xFF) << 16) |
            ((hmac_hash[dynamic_offset + 2] & 0xFF) << 8) |
            (hmac_hash[dynamic_offset + 3] & 0xFF)
        )
        otp = str(calc_code % (10 ** digits)).zfill(digits)

        if otp == code:
            return True

    return False
