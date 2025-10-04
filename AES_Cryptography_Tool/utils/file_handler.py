"""
File handling utilities
"""

import os
import subprocess
import sys

class FileHandler:
    @staticmethod
    def save_encrypted_file(filename, ciphertext, iv_nonce, mode):
        """Save encrypted data to file"""
        with open(filename, 'wb') as f:
            if mode.upper() in ['CBC', 'CFB', 'OFB', 'CTR'] and iv_nonce:
                f.write(iv_nonce)
            f.write(ciphertext)

    @staticmethod
    def try_open_file(filename):
        """Try to open a file with the default application"""
        try:
            if os.name == 'nt':  # Windows
                os.startfile(filename)
            elif sys.platform == "darwin":  # macOS
                subprocess.Popen(["open", filename])
            else:  # Linux
                subprocess.Popen(["xdg-open", filename])
            return True
        except Exception as e:
            return False