"""
AES encryption/decryption handler
"""

import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

class AESHandler:
    def __init__(self):
        pass

    def encrypt(self, plaintext, key, mode='CBC', key_size=128):
        """AES encryption function"""
        # Validate key length based on key_size
        key_length = key_size // 8
        if len(key) != key_length:
            raise ValueError(f"AES-{key_size} key must be {key_length} bytes long")

        iv_nonce = None
        start_time = time.perf_counter()

        if mode.upper() == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode.upper() == 'CBC':
            iv = get_random_bytes(16)  # AES block size is 16 bytes
            cipher = AES.new(key, AES.MODE_CBC, iv)
            iv_nonce = iv
        elif mode.upper() == 'CFB':
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CFB, iv)
            iv_nonce = iv
        elif mode.upper() == 'OFB':
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_OFB, iv)
            iv_nonce = iv
        elif mode.upper() == 'CTR':
            nonce = get_random_bytes(8)  # 8 bytes for AES CTR
            counter = Counter.new(64, prefix=nonce)  # 64-bit counter for AES
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            iv_nonce = nonce
        else:
            raise ValueError(f"Unsupported mode: {mode}")

        if mode.upper() in ['ECB', 'CBC']:
            padded_plaintext = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
        else:
            ciphertext = cipher.encrypt(plaintext)

        enc_time = time.perf_counter() - start_time

        return {
            'ciphertext': ciphertext,
            'iv_nonce': iv_nonce,
            'time': enc_time,
            'original_size': len(plaintext),
            'encrypted_size': len(ciphertext),
            'mode': mode,
            'key_size': key_size
        }

    def decrypt(self, ciphertext, key, iv_nonce, mode='CBC', key_size=128):
        """AES decryption function"""
        start_time = time.perf_counter()

        if mode.upper() == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(ciphertext)
            plaintext = unpad(decrypted, AES.block_size)
        elif mode.upper() == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv_nonce)
            decrypted = cipher.decrypt(ciphertext)
            plaintext = unpad(decrypted, AES.block_size)
        elif mode.upper() == 'CFB':
            cipher = AES.new(key, AES.MODE_CFB, iv_nonce)
            plaintext = cipher.decrypt(ciphertext)
        elif mode.upper() == 'OFB':
            cipher = AES.new(key, AES.MODE_OFB, iv_nonce)
            plaintext = cipher.decrypt(ciphertext)
        elif mode.upper() == 'CTR':
            counter = Counter.new(64, prefix=iv_nonce)
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            plaintext = cipher.decrypt(ciphertext)
        else:
            raise ValueError(f"Unsupported mode: {mode}")

        dec_time = time.perf_counter() - start_time

        return {
            'plaintext': plaintext,
            'time': dec_time,
            'decrypted_size': len(plaintext),
            'mode': mode,
            'key_size': key_size
        }

    def save_encrypted_file(self, filename, ciphertext, iv_nonce, mode):
        """Save encrypted data to file"""
        with open(filename, 'wb') as f:
            if mode.upper() in ['CBC', 'CFB', 'OFB', 'CTR'] and iv_nonce:
                f.write(iv_nonce)
            f.write(ciphertext)