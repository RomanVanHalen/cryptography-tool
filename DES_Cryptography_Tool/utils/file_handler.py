"""
File handling utilities
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox
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
    def load_encrypted_file(filepath, mode):
        """Load encrypted file and extract IV/Nonce if present"""
        with open(filepath, 'rb') as f:
            file_data = f.read()

        iv_nonce = None
        ciphertext = file_data

        if mode.upper() in ['CBC', 'CFB', 'OFB'] and len(file_data) >= 8:
            iv_nonce = file_data[:8]
            ciphertext = file_data[8:]
        elif mode.upper() == 'CTR' and len(file_data) >= 4:
            iv_nonce = file_data[:4]
            ciphertext = file_data[4:]

        return ciphertext, iv_nonce

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

    @staticmethod
    def get_file_extension(filename):
        """Get file extension"""
        return os.path.splitext(filename)[1]