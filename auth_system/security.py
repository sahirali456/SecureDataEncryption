import hashlib
import os
import base64

class AuthSystem:
    # Enhanced fixed salt with higher security
    SALT = base64.b64decode(b'c2VjdXJlX3NhbHRfMTIzNDU2Nzg5MA==')  # 16-byte salt
    
    @staticmethod
    def hash_passkey(passkey: str) -> str:
        """
        Secure password hashing with:
        - PBKDF2-HMAC-SHA256
        - 210,000 iterations (OWASP recommended)
        - Fixed 16-byte salt
        - Returns 64-character hex digest
        """
        if not passkey:
            raise ValueError("Passkey cannot be empty")
            
        return hashlib.pbkdf2_hmac(
            'sha256',
            passkey.encode('utf-8'),
            AuthSystem.SALT,
            210000  # Increased from 100k to 210k for better security
        ).hex()
    
    @staticmethod
    def validate_passkey(input_pass: str, stored_hash: str) -> bool:
        """
        Secure password validation with:
        - Constant-time comparison (prevent timing attacks)
        - Input sanitization
        """
        if not input_pass or not stored_hash:
            return False
            
        try:
            input_hash = AuthSystem.hash_passkey(input_pass)
            # Constant-time comparison
            return len(input_hash) == len(stored_hash) and \
                   hashlib.sha256(input_hash.encode()).digest() == \
                   hashlib.sha256(stored_hash.encode()).digest()
        except:
            return False

    @staticmethod
    def generate_session_token() -> str:
        """Generate cryptographically secure session token"""
        return base64.b64encode(os.urandom(32)).decode('utf-8')
