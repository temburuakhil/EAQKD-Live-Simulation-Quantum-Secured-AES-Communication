"""
AES-256-GCM Cryptographic Engine.
Uses quantum-generated symmetric keys from EAQKD for authenticated encryption and decryption.
Features:
  - Galois/Counter Mode (GCM) for authenticated encryption with associated data (AEAD)
  - 256-bit symmetric security level (immune to quantum Grover speedup)
  - Tamper detection via 128-bit cryptographic authentication tag
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class AESQuantumCipher:
    """AES-256-GCM cipher driven by EAQKD symmetric keys."""
    
    def __init__(self, key_material):
        """
        Initializes cipher with a 256-bit key.
        Accepts:
          - 32-byte bytes object
          - 64-character hexadecimal string
          - list/array of 256 bits (0s and 1s)
        """
        self.key = self._normalize_key(key_material)
        self.aesgcm = AESGCM(self.key)
        self.key_fingerprint = hashlib.sha256(self.key).hexdigest()[:16]

    @staticmethod
    def _normalize_key(key_material) -> bytes:
        if isinstance(key_material, bytes):
            if len(key_material) == 32:
                return key_material
            elif len(key_material) > 32:
                return hashlib.sha256(key_material).digest()
            else:
                return hashlib.sha256(key_material).digest()
        elif isinstance(key_material, str):
            # Check if hex string
            try:
                b = bytes.fromhex(key_material.strip())
                if len(b) == 32:
                    return b
            except ValueError:
                pass
            return hashlib.sha256(key_material.encode('utf-8')).digest()
        elif isinstance(key_material, (list, tuple)):
            # List of bits
            bit_str = "".join(str(b) for b in key_material)
            int_val = int(bit_str, 2)
            num_bytes = (len(bit_str) + 7) // 8
            raw_b = int_val.to_bytes(num_bytes, byteorder='big')
            return hashlib.sha256(raw_b).digest()
        else:
            raise TypeError("Unsupported key format. Must be bytes, hex string, or bit array.")

    def encrypt(self, plaintext: str | bytes, associated_data: str | bytes = None) -> dict:
        """
        Encrypts plaintext using AES-256-GCM with a fresh random 96-bit nonce.
        
        Returns:
            dict with {
                'ciphertext_hex': hex string of ciphertext + auth tag,
                'nonce_hex': hex string of 96-bit IV,
                'key_fingerprint': short SHA-256 key identifier,
                'payload_size_bytes': length of plaintext
            }
        """
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
            
        ad_bytes = associated_data.encode('utf-8') if isinstance(associated_data, str) else associated_data
        
        # 96-bit random nonce for GCM mode
        nonce = os.urandom(12)
        
        # AES-GCM encrypts and appends the 16-byte authentication tag
        ciphertext = self.aesgcm.encrypt(nonce, plaintext_bytes, ad_bytes)
        
        return {
            'ciphertext_hex': ciphertext.hex(),
            'nonce_hex': nonce.hex(),
            'key_fingerprint': self.key_fingerprint,
            'payload_size_bytes': len(plaintext_bytes)
        }

    def decrypt(self, ciphertext_hex: str, nonce_hex: str, associated_data: str | bytes = None) -> dict:
        """
        Decrypts ciphertext and verifies cryptographic authentication tag.
        
        Returns:
            dict with {
                'plaintext': decoded string (if valid utf-8) or raw bytes,
                'authenticated': True/False,
                'error': None or error message
            }
        """
        ad_bytes = associated_data.encode('utf-8') if isinstance(associated_data, str) else associated_data
        
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
            nonce = bytes.fromhex(nonce_hex)
            decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext, ad_bytes)
            
            try:
                plaintext_str = decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                plaintext_str = decrypted_bytes.hex()
                
            return {
                'plaintext': plaintext_str,
                'authenticated': True,
                'error': None
            }
        except InvalidTag:
            return {
                'plaintext': None,
                'authenticated': False,
                'error': "CRYPTOGRAPHIC INTEGRITY FAILURE: Invalid Authentication Tag! Data was tampered or incorrect key used."
            }
        except Exception as e:
            return {
                'plaintext': None,
                'authenticated': False,
                'error': f"Decryption error: {str(e)}"
            }
