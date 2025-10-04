"""
DES encryption/decryption handler
"""

import time
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

class DESHandler:
    def __init__(self):
        pass

    def encrypt(self, plaintext, key, mode='CBC'):
        """DES encryption function"""
        if len(key) != 8:
            raise ValueError("DES key must be 8 bytes long")

        iv_nonce = None
        start_time = time.perf_counter()

        if mode.upper() == 'ECB':
            cipher = DES.new(key, DES.MODE_ECB)
        elif mode.upper() == 'CBC':
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            iv_nonce = iv
        elif mode.upper() == 'CFB':
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_CFB, iv)
            iv_nonce = iv
        elif mode.upper() == 'OFB':
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_OFB, iv)
            iv_nonce = iv
        elif mode.upper() == 'CTR':
            nonce = get_random_bytes(4)
            counter = Counter.new(32, prefix=nonce)
            cipher = DES.new(key, DES.MODE_CTR, counter=counter)
            iv_nonce = nonce
        else:
            raise ValueError(f"Unsupported mode: {mode}")

        if mode.upper() in ['ECB', 'CBC']:
            padded_plaintext = pad(plaintext, DES.block_size)
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
            'mode': mode
        }

    def decrypt(self, ciphertext, key, iv_nonce, mode='CBC'):
        """DES decryption function"""
        start_time = time.perf_counter()

        if mode.upper() == 'ECB':
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted = cipher.decrypt(ciphertext)
            plaintext = unpad(decrypted, DES.block_size)
        elif mode.upper() == 'CBC':
            cipher = DES.new(key, DES.MODE_CBC, iv_nonce)
            decrypted = cipher.decrypt(ciphertext)
            plaintext = unpad(decrypted, DES.block_size)
        elif mode.upper() == 'CFB':
            cipher = DES.new(key, DES.MODE_CFB, iv_nonce)
            plaintext = cipher.decrypt(ciphertext)
        elif mode.upper() == 'OFB':
            cipher = DES.new(key, DES.MODE_OFB, iv_nonce)
            plaintext = cipher.decrypt(ciphertext)
        elif mode.upper() == 'CTR':
            counter = Counter.new(32, prefix=iv_nonce)
            cipher = DES.new(key, DES.MODE_CTR, counter=counter)
            plaintext = cipher.decrypt(ciphertext)
        else:
            raise ValueError(f"Unsupported mode: {mode}")

        dec_time = time.perf_counter() - start_time

        return {
            'plaintext': plaintext,
            'time': dec_time,
            'decrypted_size': len(plaintext),
            'mode': mode
        }

    def save_encrypted_file(self, filename, ciphertext, iv_nonce, mode):
        """Save encrypted data to file"""
        with open(filename, 'wb') as f:
            if mode.upper() in ['CBC', 'CFB', 'OFB', 'CTR'] and iv_nonce:
                f.write(iv_nonce)
            f.write(ciphertext)