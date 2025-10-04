"""
AES Encryption tab implementation
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from crypto.aes_handler import AESHandler


class AESEncryptionTab:
    def __init__(self, parent, colors):
        self.parent = parent
        self.colors = colors
        self.aes_handler = AESHandler()
        self.status_var = None
        self.create_interface()

    def set_status_var(self, status_var):
        """Set status variable for updating status bar"""
        self.status_var = status_var

    def create_interface(self):
        """Create the encryption tab interface"""
        self.frame = ttk.Frame(self.parent)

        # Input section
        input_frame = ttk.LabelFrame(self.frame, text="AES Encryption Settings", padding="15")
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        # Input method
        ttk.Label(input_frame, text="Input Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_var = tk.StringVar(value="text")
        ttk.Radiobutton(input_frame, text="Text", variable=self.input_var,
                        value="text").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(input_frame, text="File", variable=self.input_var,
                        value="file").grid(row=0, column=2, sticky=tk.W)

        # Text input
        self.text_frame = ttk.Frame(input_frame)
        self.text_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.text_frame, text="Input Text:").pack(anchor=tk.W)
        self.text_input = scrolledtext.ScrolledText(self.text_frame, height=4, width=80)
        self.text_input.pack(fill=tk.X, pady=5)

        # File input
        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.file_frame, text="Select File:").pack(anchor=tk.W)
        file_select_frame = ttk.Frame(self.file_frame)
        file_select_frame.pack(fill=tk.X, pady=5)
        self.file_path = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)

        # AES-specific settings
        settings_frame = ttk.Frame(input_frame)
        settings_frame.grid(row=3, column=0, columnspan=3, sticky=tk.W + tk.E, pady=10)

        # Key size selection
        ttk.Label(settings_frame, text="AES Key Size:").grid(row=0, column=0, sticky=tk.W)
        self.key_size_var = tk.StringVar(value="128")
        key_size_frame = ttk.Frame(settings_frame)
        key_size_frame.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(key_size_frame, text="128-bit", variable=self.key_size_var,
                        value="128").pack(side=tk.LEFT)
        ttk.Radiobutton(key_size_frame, text="192-bit", variable=self.key_size_var,
                        value="192").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(key_size_frame, text="256-bit", variable=self.key_size_var,
                        value="256").pack(side=tk.LEFT)

        # Key entry
        ttk.Label(settings_frame, text="AES Key:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(settings_frame, width=30, font=('Arial', 10))
        self.key_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.key_entry.insert(0, "16bytekey12345678")  # Default 128-bit key

        # Key helper label
        key_helper = ttk.Label(settings_frame,
                               text="(16 chars for 128-bit, 24 chars for 192-bit, 32 chars for 256-bit)")
        key_helper.grid(row=1, column=2, sticky=tk.W, padx=10)

        # Encryption mode
        ttk.Label(settings_frame, text="Encryption Mode:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.mode_combo = ttk.Combobox(settings_frame, values=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
                                       state="readonly", width=15)
        self.mode_combo.set('CBC')
        self.mode_combo.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Encrypt", command=self.process_encryption,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Output section
        output_frame = ttk.LabelFrame(self.frame, text="AES Encryption Results", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=8)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Download buttons
        button_frame_out = ttk.Frame(output_frame)
        button_frame_out.pack(pady=5)

        self.download_btn = ttk.Button(button_frame_out, text="Download Encrypted File",
                                       command=self.download_result, state='disabled')
        self.download_btn.pack(side=tk.LEFT, padx=5)

        self.copy_btn = ttk.Button(button_frame_out, text="Copy Ciphertext",
                                   command=self.copy_ciphertext, state='disabled')
        self.copy_btn.pack(side=tk.LEFT, padx=5)

        # Initialize
        self.toggle_input()
        self.input_var.trace('w', lambda *args: self.toggle_input())
        self.key_size_var.trace('w', lambda *args: self.update_key_placeholder())

    def toggle_input(self):
        """Toggle between text and file input"""
        if self.input_var.get() == "text":
            self.text_frame.grid()
            self.file_frame.grid_remove()
        else:
            self.text_frame.grid_remove()
            self.file_frame.grid()

    def update_key_placeholder(self):
        """Update key entry placeholder based on selected key size"""
        key_size = int(self.key_size_var.get())
        required_chars = key_size // 8

        # Clear current entry and set new placeholder
        current_text = self.key_entry.get()
        if len(current_text) == required_chars:
            return  # Keep current text if it's already correct length

        # Set example key based on size
        if key_size == 128:
            example = "16bytekey12345678"
        elif key_size == 192:
            example = "24bytekey12345678901234"
        else:  # 256
            example = "32bytekey1234567890123456789012"

        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, example)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            self.original_extension = os.path.splitext(filename)[1]

    def process_encryption(self):
        """Handle AES encryption process"""
        try:
            if self.status_var:
                self.status_var.set("Processing AES encryption...")

            if self.input_var.get() == "text":
                plaintext = self.text_input.get(1.0, tk.END).strip().encode('utf-8')
                if not plaintext:
                    messagebox.showerror("Error", "Please enter some text to encrypt")
                    return
                input_type = "text"
            else:
                filepath = self.file_path.get()
                if not filepath or not os.path.exists(filepath):
                    messagebox.showerror("Error", "Please select a valid file")
                    return
                with open(filepath, 'rb') as f:
                    plaintext = f.read()
                input_type = "file"
                self.original_extension = os.path.splitext(filepath)[1]

            key_str = self.key_entry.get().strip()
            key_size = int(self.key_size_var.get())
            required_length = key_size // 8

            if len(key_str) != required_length:
                messagebox.showerror("Error",
                                     f"AES-{key_size} key must be exactly {required_length} characters")
                return

            mode = self.mode_combo.get()
            result = self.aes_handler.encrypt(plaintext, key_str.encode('utf-8'), mode, key_size)

            self.display_results(result, input_type)
            self.last_result = result
            self.last_input_type = input_type

            if input_type == "file":
                self.last_original_extension = self.original_extension

            self.download_btn.config(state='normal')
            self.copy_btn.config(state='normal' if input_type == "text" else 'disabled')

            if self.status_var:
                self.status_var.set("AES encryption completed successfully")

        except Exception as e:
            messagebox.showerror("Error", f"AES encryption failed: {str(e)}")
            if self.status_var:
                self.status_var.set("AES encryption failed")

    def display_results(self, result, input_type):
        """Display AES encryption results"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "AES ENCRYPTION SUCCESSFUL\n")
        self.output_text.insert(tk.END, "=" * 50 + "\n\n")
        self.output_text.insert(tk.END, f"Key Size: AES-{result['key_size']}\n")
        self.output_text.insert(tk.END, f"Mode: {result['mode']}\n")
        self.output_text.insert(tk.END, f"Encryption Time: {result['time'] * 1000:.3f} ms\n")
        self.output_text.insert(tk.END, f"Original Size: {result['original_size']} bytes\n")
        self.output_text.insert(tk.END, f"Encrypted Size: {result['encrypted_size']} bytes\n")

        if result['iv_nonce']:
            self.output_text.insert(tk.END, f"IV/Nonce: {result['iv_nonce'].hex()}\n")

        if input_type == "text":
            self.output_text.insert(tk.END, f"\nCiphertext (hex):\n")
            self.output_text.insert(tk.END, f"{result['ciphertext'].hex()}\n")
        else:
            self.output_text.insert(tk.END,
                                    f"\nFile encrypted successfully. Use 'Download Encrypted File' to save the result.\n")

    def download_result(self):
        """Download encryption result"""
        if not hasattr(self, 'last_result'):
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".aes",
            filetypes=[("AES Encrypted files", "*.aes"), ("All files", "*.*")]
        )

        if filename:
            try:
                self.aes_handler.save_encrypted_file(
                    filename,
                    self.last_result['ciphertext'],
                    self.last_result['iv_nonce'],
                    self.last_result['mode']
                )
                messagebox.showinfo("Success", f"Encrypted file saved as {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save encrypted file: {str(e)}")

    def copy_ciphertext(self):
        """Copy ciphertext to clipboard"""
        if hasattr(self, 'last_result'):
            self.frame.clipboard_clear()
            self.frame.clipboard_append(self.last_result['ciphertext'].hex())
            self.frame.update()
            messagebox.showinfo("Copied", "Ciphertext copied to clipboard")

    def clear(self):
        """Clear inputs/outputs"""
        self.text_input.delete(1.0, tk.END)
        self.file_path.set("")
        self.output_text.delete(1.0, tk.END)
        self.download_btn.config(state='disabled')
        self.copy_btn.config(state='disabled')