"""
RSA encryption/decryption handler using cryptography library
"""

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class RSAHandler:
    def __init__(self):
        pass

    def generate_key_pair(self, key_size=2048, public_exponent=65537):
        """
        Generate RSA key pair

        Args:
            key_size (int): Key size in bits (1024, 2048, 4096)
            public_exponent (int): Public exponent (usually 65537)

        Returns:
            dict: Contains public and private keys in PEM format
        """
        if key_size not in [1024, 2048, 4096]:
            raise ValueError("Key size must be 1024, 2048, or 4096 bits")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )

        # Get public key
        public_key = private_key.public_key()

        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Get key information
        public_numbers = public_key.public_numbers()

        return {
            'private_key_pem': private_pem,
            'public_key_pem': public_pem,
            'key_size': key_size,
            'public_exponent': public_exponent,
            'modulus_hex': hex(public_numbers.n)[2:],
            'public_exponent_value': public_numbers.e
        }

    def encrypt(self, data, public_key_pem):
        """
        Encrypt data using RSA public key

        Args:
            data (bytes): Data to encrypt
            public_key_pem (str): Public key in PEM format

        Returns:
            str: Base64 encoded ciphertext
        """
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        # Encrypt the data
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Encode as base64 for easy storage/transmission
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext_b64, private_key_pem):
        """
        Decrypt data using RSA private key

        Args:
            ciphertext_b64 (str): Base64 encoded ciphertext
            private_key_pem (str): Private key in PEM format

        Returns:
            bytes: Decrypted data
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        # Decode base64
        ciphertext = base64.b64decode(ciphertext_b64)

        # Decrypt the data
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plaintext

    def get_key_size_from_pem(self, public_key_pem):
        """
        Get key size from PEM public key

        Args:
            public_key_pem (str): Public key in PEM format

        Returns:
            int: Key size in bits
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        # Get key size from modulus bit length
        public_numbers = public_key.public_numbers()
        return public_numbers.n.bit_length()

    def get_max_encryption_size(self, key_size):
        """
        Get maximum encryption size for a given key size

        Args:
            key_size (int): Key size in bits

        Returns:
            int: Maximum number of bytes that can be encrypted
        """
        # RSA can encrypt data up to (key_size/8 - padding) bytes
        # For OAEP with SHA-256: padding = 2 * hash_size + 2 = 2*32 + 2 = 66 bytes
        return (key_size // 8) - 66

    def sign_data(self, data, private_key_pem):
        """
        Sign data using RSA private key

        Args:
            data (bytes): Data to sign
            private_key_pem (str): Private key in PEM format

        Returns:
            str: Base64 encoded signature
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, data, signature_b64, public_key_pem):
        """
        Verify signature using RSA public key

        Args:
            data (bytes): Original data
            signature_b64 (str): Base64 encoded signature
            public_key_pem (str): Public key in PEM format

        Returns:
            bool: True if signature is valid
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        signature = base64.b64decode(signature_b64)

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def get_key_info(self, key_pem):
        """
        Get information about RSA key

        Args:
            key_pem (str): RSA key in PEM format

        Returns:
            dict: Key information
        """
        try:
            # Try to load as public key first
            key = serialization.load_pem_public_key(
                key_pem.encode('utf-8'),
                backend=default_backend()
            )
            key_type = "public"
        except:
            try:
                # Try to load as private key
                key = serialization.load_pem_private_key(
                    key_pem.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                key_type = "private"
            except:
                raise ValueError("Invalid PEM key format")

        if key_type == "public":
            public_numbers = key.public_numbers()
            return {
                'type': 'public',
                'key_size': public_numbers.n.bit_length(),
                'modulus': hex(public_numbers.n)[2:],
                'public_exponent': public_numbers.e
            }
        else:
            public_numbers = key.public_key().public_numbers()
            return {
                'type': 'private',
                'key_size': public_numbers.n.bit_length(),
                'modulus': hex(public_numbers.n)[2:],
                'public_exponent': public_numbers.e
            }