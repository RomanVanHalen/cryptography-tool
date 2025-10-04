#!/usr/bin/env python3

import tkinter as tk
from gui.main_window import DESCryptoTool

def main():

    root = tk.Tk()
    app = DESCryptoTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()