#!/usr/bin/env python3


import tkinter as tk
from gui.main_window import AESCryptoTool

def main():

    root = tk.Tk()
    app = AESCryptoTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()