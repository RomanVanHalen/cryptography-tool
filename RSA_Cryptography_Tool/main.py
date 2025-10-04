#!/usr/bin/env python3
"""
RSA Cryptography Tool - Main Entry Point
"""

import tkinter as tk
import sys
import os

# Add the current directory to Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from gui.main_window import RSACryptoTool

def main():
    """Main function to start the RSA application"""
    root = tk.Tk()
    app = RSACryptoTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()