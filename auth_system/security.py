import hashlib
import os

class AuthSystem:
    @staticmethod
    def hash_passkey(passkey: str, salt=None) -> str:
        if not salt:
            salt = os.urandom(16)
        return hashlib.pbkdf2_hmac(
            'sha256',
            passkey.encode(),
            salt,
            100000
        ).hex()
    
    @staticmethod
    def validate_passkey(input_passkey: str, stored_hash: str) -> bool:
        return AuthSystem.hash_passkey(input_passkey) == stored_hash