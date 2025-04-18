import hashlib
import os

class AuthSystem:
    # Use FIXED salt for consistent hashing
    SALT = b'secure_salt_123'  # Important: Must be bytes
    
    @staticmethod
    def hash_passkey(passkey: str) -> str:
        """Consistent hashing with fixed salt"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            passkey.encode('utf-8'),
            AuthSystem.SALT,  # Using fixed salt
            100000
        ).hex()
    
    @staticmethod
    def validate_passkey(input_pass: str, stored_hash: str) -> bool:
        """Compare hashes using same salt"""
        return AuthSystem.hash_passkey(input_pass) == stored_hash
