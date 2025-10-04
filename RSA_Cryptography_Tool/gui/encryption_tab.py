"""
RSA Encryption tab
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
from crypto.rsa_handler import RSAHandler


class RSAEncryptionTab:
    def __init__(self, parent, colors):
        self.parent = parent
        self.colors = colors
        self.rsa_handler = RSAHandler()
        self.status_var = None
        self.create_interface()

    def set_status_var(self, status_var):
        """Set status variable for updating status bar"""
        self.status_var = status_var

    def create_interface(self):
        """Create the encryption tab interface"""
        self.frame = ttk.Frame(self.parent)

        # Input section
        input_frame = ttk.LabelFrame(self.frame, text="RSA Encryption Input", padding="15")
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        # Input type
        ttk.Label(input_frame, text="Input Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_var = tk.StringVar(value="text")
        ttk.Radiobutton(input_frame, text="Text", variable=self.input_var,
                        value="text").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(input_frame, text="File", variable=self.input_var,
                        value="file").grid(row=0, column=2, sticky=tk.W)

        # Text input
        self.text_frame = ttk.Frame(input_frame)
        self.text_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.text_frame, text="Text to Encrypt:").pack(anchor=tk.W)
        self.text_input = scrolledtext.ScrolledText(self.text_frame, height=4, width=80)
        self.text_input.pack(fill=tk.X, pady=5)

        # File input
        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.file_frame, text="File to Encrypt:").pack(anchor=tk.W)
        file_select_frame = ttk.Frame(self.file_frame)
        file_select_frame.pack(fill=tk.X, pady=5)
        self.file_path = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)

        # Public key input
        key_frame = ttk.Frame(input_frame)
        key_frame.grid(row=3, column=0, columnspan=3, sticky=tk.W + tk.E, pady=10)
        ttk.Label(key_frame, text="Public Key (PEM format):").pack(anchor=tk.W)
        self.public_key_input = scrolledtext.ScrolledText(key_frame, height=6, width=80)
        self.public_key_input.pack(fill=tk.X, pady=5)

        # Public key file load
        key_file_frame = ttk.Frame(key_frame)
        key_file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(key_file_frame, text="Load Public Key from File",
                   command=self.load_public_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_file_frame, text="Paste from Key Generation",
                   command=self.paste_public_key).pack(side=tk.LEFT, padx=5)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Output section
        output_frame = ttk.LabelFrame(self.frame, text="Encryption Result", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Ciphertext output
        ttk.Label(output_frame, text="Ciphertext (Base64):").pack(anchor=tk.W)
        self.ciphertext_output = scrolledtext.ScrolledText(output_frame, height=6, width=80)
        self.ciphertext_output.pack(fill=tk.X, pady=5)

        # Ciphertext actions
        cipher_actions = ttk.Frame(output_frame)
        cipher_actions.pack(fill=tk.X, pady=5)
        self.copy_cipher_btn = ttk.Button(cipher_actions, text="Copy Ciphertext",
                                          command=self.copy_ciphertext, state='disabled')
        self.copy_cipher_btn.pack(side=tk.LEFT, padx=5)
        self.save_cipher_btn = ttk.Button(cipher_actions, text="Save Ciphertext",
                                          command=self.save_ciphertext, state='disabled')
        self.save_cipher_btn.pack(side=tk.LEFT, padx=5)

        # Encryption info
        info_frame = ttk.LabelFrame(output_frame, text="Encryption Information", padding="10")
        info_frame.pack(fill=tk.X, pady=10)

        self.info_text = scrolledtext.ScrolledText(info_frame, height=4, width=80)
        self.info_text.pack(fill=tk.X)

        # Initialize
        self.toggle_input()
        self.input_var.trace('w', lambda *args: self.toggle_input())

    def toggle_input(self):
        """Toggle between text and file input"""
        if self.input_var.get() == "text":
            self.text_frame.grid()
            self.file_frame.grid_remove()
        else:
            self.text_frame.grid_remove()
            self.file_frame.grid()

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def load_public_key(self):
        """Load public key from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    public_key = f.read()
                self.public_key_input.delete(1.0, tk.END)
                self.public_key_input.insert(tk.END, public_key)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load public key: {str(e)}")

    def paste_public_key(self):
        """Paste public key from clipboard"""
        try:
            clipboard_content = self.frame.clipboard_get()
            self.public_key_input.delete(1.0, tk.END)
            self.public_key_input.insert(tk.END, clipboard_content)
        except:
            messagebox.showwarning("Warning", "No content in clipboard or invalid format")

    def encrypt(self):
        """Perform RSA encryption"""
        try:
            if self.status_var:
                self.status_var.set("Performing RSA encryption...")

            # Get public key
            public_key_pem = self.public_key_input.get(1.0, tk.END).strip()
            if not public_key_pem:
                messagebox.showerror("Error", "Please provide a public key")
                return

            # Get data to encrypt
            if self.input_var.get() == "text":
                plaintext = self.text_input.get(1.0, tk.END).strip()
                if not plaintext:
                    messagebox.showerror("Error", "Please enter text to encrypt")
                    return

                input_type = "text"
                input_data = plaintext.encode('utf-8')
                input_size = len(input_data)

            else:
                filepath = self.file_path.get()
                if not filepath or not os.path.exists(filepath):
                    messagebox.showerror("Error", "Please select a valid file")
                    return

                with open(filepath, 'rb') as f:
                    input_data = f.read()

                input_type = "file"
                input_size = len(input_data)
                filename = os.path.basename(filepath)

            # Check input size limit (RSA has limitations)
            key_size = self.rsa_handler.get_key_size_from_pem(public_key_pem)
            max_size = self.rsa_handler.get_max_encryption_size(key_size)

            if input_size > max_size:
                messagebox.showerror("Error",
                                     f"Input too large for RSA encryption.\n"
                                     f"Maximum for {key_size}-bit key: {max_size} bytes\n"
                                     f"Your input: {input_size} bytes\n\n"
                                     f"Consider using hybrid encryption (RSA + AES) for large files.")
                return

            start_time = time.perf_counter()
            ciphertext_b64 = self.rsa_handler.encrypt(input_data, public_key_pem)
            end_time = time.perf_counter()

            encryption_time = end_time - start_time

            # Display results
            self.ciphertext_output.delete(1.0, tk.END)
            self.ciphertext_output.insert(tk.END, ciphertext_b64)

            # Display information
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, f"Input Type: {input_type}\n")
            if input_type == "file":
                self.info_text.insert(tk.END, f"File: {filename}\n")
            self.info_text.insert(tk.END, f"Input Size: {input_size} bytes\n")
            self.info_text.insert(tk.END, f"Key Size: {key_size} bits\n")
            self.info_text.insert(tk.END, f"Encryption Time: {encryption_time * 1000:.3f} ms\n")
            self.info_text.insert(tk.END, f"Ciphertext Size: {len(ciphertext_b64)} characters\n")

            self.last_ciphertext = ciphertext_b64
            self.copy_cipher_btn.config(state='normal')
            self.save_cipher_btn.config(state='normal')

            if self.status_var:
                self.status_var.set("RSA encryption completed successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            if self.status_var:
                self.status_var.set("Encryption failed")

    def copy_ciphertext(self):
        """Copy ciphertext to clipboard"""
        if hasattr(self, 'last_ciphertext'):
            self.frame.clipboard_clear()
            self.frame.clipboard_append(self.last_ciphertext)
            self.frame.update()
            messagebox.showinfo("Copied", "Ciphertext copied to clipboard")

    def save_ciphertext(self):
        """Save ciphertext to file"""
        if not hasattr(self, 'last_ciphertext'):
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.last_ciphertext)
                messagebox.showinfo("Success", f"Ciphertext saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save ciphertext: {str(e)}")

    def clear(self):
        """Clear all inputs and outputs"""
        self.text_input.delete(1.0, tk.END)
        self.file_path.set("")
        self.public_key_input.delete(1.0, tk.END)
        self.ciphertext_output.delete(1.0, tk.END)
        self.info_text.delete(1.0, tk.END)
        self.copy_cipher_btn.config(state='disabled')
        self.save_cipher_btn.config(state='disabled')