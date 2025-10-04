#!/usr/bin/env python3
"""
SHA-256 Hash Tool - Main Entry Point
"""

import tkinter as tk
from gui.main_window import SHA256HashTool

def main():
    """Main function to start the SHA-256 application"""
    root = tk.Tk()
    app = SHA256HashTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()