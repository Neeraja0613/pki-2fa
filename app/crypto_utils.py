import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def decrypt_seed(encrypted_seed_b64: str):
    # Load private key from correct folder
    private_key = load_private_key("keys/private_key.pem")

    # Base64 decode the encrypted seed
    encrypted_seed = base64.b64decode(encrypted_seed_b64)

    # Decrypt using OAEP SHA256
    decrypted = private_key.decrypt(
        encrypted_seed,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return decrypted seed as string
    return decrypted.decode()
