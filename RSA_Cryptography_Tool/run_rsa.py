#!/usr/bin/env python3
"""
RSA Crypto Tool - Launcher
"""

import sys
import os

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from main import main

if __name__ == "__main__":
    main()