"""
SHA-256 hashing handler
"""

import hashlib
import os


class HashHandler:
    def __init__(self):
        pass

    def hash_text(self, text):
        """
        Generate SHA-256 hash for text

        Args:
            text (str): Input text to hash

        Returns:
            str: SHA-256 hash as hexadecimal string
        """
        if not text:
            raise ValueError("Text cannot be empty")

        # Create SHA-256 hash object
        sha256_hash = hashlib.sha256()

        # Update hash with text encoded as UTF-8
        sha256_hash.update(text.encode('utf-8'))

        # Return hexadecimal digest
        return sha256_hash.hexdigest()

    def hash_file(self, filepath, chunk_size=8192):
        """
        Generate SHA-256 hash for file

        Args:
            filepath (str): Path to file to hash
            chunk_size (int): Size of chunks to read file in

        Returns:
            str: SHA-256 hash as hexadecimal string
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        if not os.path.isfile(filepath):
            raise ValueError(f"Path is not a file: {filepath}")

        # Create SHA-256 hash object
        sha256_hash = hashlib.sha256()

        # Read file in chunks to handle large files efficiently
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    def verify_text_hash(self, text, expected_hash):
        """
        Verify SHA-256 hash for text

        Args:
            text (str): Text to verify
            expected_hash (str): Expected SHA-256 hash

        Returns:
            tuple: (bool, str) - (True if match, actual hash)
        """
        actual_hash = self.hash_text(text)
        return actual_hash == expected_hash.lower().replace(' ', '').replace('-', ''), actual_hash

    def verify_file_hash(self, filepath, expected_hash):
        """
        Verify SHA-256 hash for file

        Args:
            filepath (str): Path to file to verify
            expected_hash (str): Expected SHA-256 hash

        Returns:
            tuple: (bool, str) - (True if match, actual hash)
        """
        actual_hash = self.hash_file(filepath)
        return actual_hash == expected_hash.lower().replace(' ', '').replace('-', ''), actual_hash

    def get_hash_info(self):
        """
        Get information about SHA-256 algorithm

        Returns:
            dict: Information about SHA-256
        """
        return {
            'algorithm': 'SHA-256',
            'hash_size': 256,  # bits
            'hash_length': 64,  # hexadecimal characters
            'block_size': 64,  # bytes
            'word_size': 32,  # bits
            'security_level': 'High',
            'common_uses': [
                'Digital signatures',
                'Certificate authorities',
                'Blockchain technology',
                'Data integrity verification',
                'Password hashing (with salt)'
            ]
        }