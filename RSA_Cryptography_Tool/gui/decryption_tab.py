"""
RSA Decryption tab
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
from crypto.rsa_handler import RSAHandler

class RSADecryptionTab:
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
        """Create the decryption tab interface"""
        self.frame = ttk.Frame(self.parent)

        # Input section
        input_frame = ttk.LabelFrame(self.frame, text="RSA Decryption Input", padding="15")
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        # Ciphertext input
        ttk.Label(input_frame, text="Ciphertext (Base64):").pack(anchor=tk.W)
        self.ciphertext_input = scrolledtext.ScrolledText(input_frame, height=6, width=80)
        self.ciphertext_input.pack(fill=tk.X, pady=5)

        # Ciphertext file load
        cipher_file_frame = ttk.Frame(input_frame)
        cipher_file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(cipher_file_frame, text="Load Ciphertext from File",
                  command=self.load_ciphertext).pack(side=tk.LEFT, padx=5)

        # Private key input
        key_frame = ttk.Frame(input_frame)
        key_frame.pack(fill=tk.X, pady=10)
        ttk.Label(key_frame, text="Private Key (PEM format):").pack(anchor=tk.W)
        self.private_key_input = scrolledtext.ScrolledText(key_frame, height=6, width=80)
        self.private_key_input.pack(fill=tk.X, pady=5)

        # Private key file load
        key_file_frame = ttk.Frame(key_frame)
        key_file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(key_file_frame, text="Load Private Key from File",
                  command=self.load_private_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_file_frame, text="Paste from Key Generation",
                  command=self.paste_private_key).pack(side=tk.LEFT, padx=5)

        # Action buttons - FIXED: Use pack instead of grid
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill=tk.X, pady=10)  # Changed from grid to pack
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Output section
        output_frame = ttk.LabelFrame(self.frame, text="Decryption Result", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Decrypted output
        ttk.Label(output_frame, text="Decrypted Data:").pack(anchor=tk.W)
        self.decrypted_output = scrolledtext.ScrolledText(output_frame, height=6, width=80)
        self.decrypted_output.pack(fill=tk.X, pady=5)

        # Decrypted data actions
        decrypted_actions = ttk.Frame(output_frame)
        decrypted_actions.pack(fill=tk.X, pady=5)
        self.copy_decrypted_btn = ttk.Button(decrypted_actions, text="Copy Decrypted Text",
                                           command=self.copy_decrypted, state='disabled')
        self.copy_decrypted_btn.pack(side=tk.LEFT, padx=5)
        self.save_decrypted_btn = ttk.Button(decrypted_actions, text="Save Decrypted Data",
                                           command=self.save_decrypted, state='disabled')
        self.save_decrypted_btn.pack(side=tk.LEFT, padx=5)

        # Decryption info
        info_frame = ttk.LabelFrame(output_frame, text="Decryption Information", padding="10")
        info_frame.pack(fill=tk.X, pady=10)

        self.info_text = scrolledtext.ScrolledText(info_frame, height=4, width=80)
        self.info_text.pack(fill=tk.X)

    def load_ciphertext(self):
        """Load ciphertext from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("Encrypted files", "*.enc"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    ciphertext = f.read()
                self.ciphertext_input.delete(1.0, tk.END)
                self.ciphertext_input.insert(tk.END, ciphertext)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load ciphertext: {str(e)}")

    def load_private_key(self):
        """Load private key from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    private_key = f.read()
                self.private_key_input.delete(1.0, tk.END)
                self.private_key_input.insert(tk.END, private_key)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load private key: {str(e)}")

    def paste_private_key(self):
        """Paste private key from clipboard"""
        try:
            clipboard_content = self.frame.clipboard_get()
            self.private_key_input.delete(1.0, tk.END)
            self.private_key_input.insert(tk.END, clipboard_content)
        except:
            messagebox.showwarning("Warning", "No content in clipboard or invalid format")

    def decrypt(self):
        """Perform RSA decryption"""
        try:
            if self.status_var:
                self.status_var.set("Performing RSA decryption...")

            # Get ciphertext
            ciphertext_b64 = self.ciphertext_input.get(1.0, tk.END).strip()
            if not ciphertext_b64:
                messagebox.showerror("Error", "Please provide ciphertext to decrypt")
                return

            # Get private key
            private_key_pem = self.private_key_input.get(1.0, tk.END).strip()
            if not private_key_pem:
                messagebox.showerror("Error", "Please provide a private key")
                return

            start_time = time.perf_counter()
            decrypted_data = self.rsa_handler.decrypt(ciphertext_b64, private_key_pem)
            end_time = time.perf_counter()

            decryption_time = end_time - start_time

            # Try to decode as text, otherwise show as hex
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                is_text = True
            except:
                decrypted_text = decrypted_data.hex()
                is_text = False

            # Display results
            self.decrypted_output.delete(1.0, tk.END)
            self.decrypted_output.insert(tk.END, decrypted_text)

            # Display information
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, f"Data Type: {'Text' if is_text else 'Binary'}\n")
            self.info_text.insert(tk.END, f"Decrypted Size: {len(decrypted_data)} bytes\n")
            self.info_text.insert(tk.END, f"Decryption Time: {decryption_time * 1000:.3f} ms\n")

            if is_text:
                self.info_text.insert(tk.END, f"Text Length: {len(decrypted_text)} characters\n")
            else:
                self.info_text.insert(tk.END, f"Hex Length: {len(decrypted_text)} characters\n")

            self.last_decrypted_data = decrypted_data
            self.last_is_text = is_text
            self.copy_decrypted_btn.config(state='normal')
            self.save_decrypted_btn.config(state='normal')

            if self.status_var:
                self.status_var.set("RSA decryption completed successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            if self.status_var:
                self.status_var.set("Decryption failed")

    def copy_decrypted(self):
        """Copy decrypted text to clipboard"""
        if hasattr(self, 'last_decrypted_data'):
            if self.last_is_text:
                text_to_copy = self.last_decrypted_data.decode('utf-8')
            else:
                text_to_copy = self.last_decrypted_data.hex()

            self.frame.clipboard_clear()
            self.frame.clipboard_append(text_to_copy)
            self.frame.update()
            messagebox.showinfo("Copied", "Decrypted data copied to clipboard")

    def save_decrypted(self):
        """Save decrypted data to file"""
        if not hasattr(self, 'last_decrypted_data'):
            return

        filename = filedialog.asksaveasfilename(
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("Binary files", "*.bin")]
        )

        if filename:
            try:
                if self.last_is_text:
                    # Save as text
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(self.last_decrypted_data.decode('utf-8'))
                else:
                    # Save as binary
                    with open(filename, 'wb') as f:
                        f.write(self.last_decrypted_data)

                messagebox.showinfo("Success", f"Decrypted data saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save decrypted data: {str(e)}")

    def clear(self):
        """Clear all inputs and outputs"""
        self.ciphertext_input.delete(1.0, tk.END)
        self.private_key_input.delete(1.0, tk.END)
        self.decrypted_output.delete(1.0, tk.END)
        self.info_text.delete(1.0, tk.END)
        self.copy_decrypted_btn.config(state='disabled')
        self.save_decrypted_btn.config(state='disabled')