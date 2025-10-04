"""
Main application window for AES Crypto Tool
"""

import tkinter as tk
from tkinter import ttk
from .encryption_tab import AESEncryptionTab
from .decryption_tab import AESDecryptionTab


class AESCryptoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Cryptography Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg='white')

        self.colors = {
            'bg': 'white', 'fg': '#333333', 'accent': '#2563EB',
            'button_bg': '#2563EB', 'button_fg': 'white',
            'group_bg': '#F8FAFC', 'border': '#E2E8F0'
        }

        self.setup_styles()
        self.create_main_interface()

    def setup_styles(self):
        """Configure clean, professional styles"""
        style = ttk.Style()
        style.theme_use('clam')

        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TLabelframe', background=self.colors['group_bg'], bordercolor=self.colors['border'])
        style.configure('TLabelframe.Label', background=self.colors['group_bg'], foreground=self.colors['fg'])
        style.configure('Accent.TButton', background=self.colors['button_bg'], foreground=self.colors['button_fg'])

        style.configure('TNotebook', background=self.colors['bg'])
        style.configure('TNotebook.Tab', background='#E2E8F0', padding=[15, 5])
        style.map('TNotebook.Tab', background=[('selected', self.colors['accent'])],
                  foreground=[('selected', 'white')])

    def create_main_interface(self):
        """Create the main application interface"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="AES Cryptography Tool",
                                font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 10))

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs
        self.encryption_tab = AESEncryptionTab(self.notebook, self.colors)
        self.decryption_tab = AESDecryptionTab(self.notebook, self.colors)

        self.notebook.add(self.encryption_tab.frame, text="AES Encryption")
        self.notebook.add(self.decryption_tab.frame, text="AES Decryption")

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var)
        status_bar.pack(fill=tk.X, pady=(10, 0))

        # Set status variable for tabs to update
        self.encryption_tab.set_status_var(self.status_var)
        self.decryption_tab.set_status_var(self.status_var)