import os, base64, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SHARED_SECRET = b"WokiToki_AES_Key_Super_Secret_32"  # 32 bytes = AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100_000, backend=default_backend())
    return kdf.derive(password.encode())


def aes_encrypt(plaintext: str, key: bytes = SHARED_SECRET) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(iv + ct).decode()


def aes_decrypt(token: str, key: bytes = SHARED_SECRET) -> str:
    raw = base64.b64decode(token)
    iv, ct = raw[:16], raw[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000).hex()
