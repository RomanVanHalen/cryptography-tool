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

        # Main container with better spacing
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Input section
        input_frame = ttk.LabelFrame(main_container, text="RSA Decryption Input", padding="15")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # Ciphertext input
        ttk.Label(input_frame, text="Ciphertext (Base64):").pack(anchor=tk.W)
        ciphertext_container = ttk.Frame(input_frame)
        ciphertext_container.pack(fill=tk.X, pady=5)

        self.ciphertext_input = scrolledtext.ScrolledText(ciphertext_container, height=4, width=80)
        self.ciphertext_input.pack(fill=tk.X, side=tk.LEFT, expand=True)

        # Ciphertext copy button
        cipher_copy_frame = ttk.Frame(ciphertext_container)
        cipher_copy_frame.pack(side=tk.RIGHT, padx=(5, 0))
        self.copy_cipher_input_btn = ttk.Button(cipher_copy_frame, text="📋",
                                              command=self.copy_ciphertext_input, width=3)
        self.copy_cipher_input_btn.pack(pady=2)

        # Ciphertext file load
        cipher_file_frame = ttk.Frame(input_frame)
        cipher_file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(cipher_file_frame, text="Load Ciphertext from File",
                  command=self.load_ciphertext).pack(side=tk.LEFT, padx=5)

        # Ciphertext info
        self.ciphertext_info_label = ttk.Label(input_frame, text="", foreground="gray")
        self.ciphertext_info_label.pack(anchor=tk.W)

        # Private key input
        key_frame = ttk.Frame(input_frame)
        key_frame.pack(fill=tk.X, pady=10)
        ttk.Label(key_frame, text="Private Key (PEM format):").pack(anchor=tk.W)

        private_key_container = ttk.Frame(key_frame)
        private_key_container.pack(fill=tk.X, pady=5)

        self.private_key_input = scrolledtext.ScrolledText(private_key_container, height=4, width=80)
        self.private_key_input.pack(fill=tk.X, side=tk.LEFT, expand=True)

        # Private key copy button
        priv_key_copy_frame = ttk.Frame(private_key_container)
        priv_key_copy_frame.pack(side=tk.RIGHT, padx=(5, 0))
        self.copy_priv_key_btn = ttk.Button(priv_key_copy_frame, text="📋",
                                          command=self.copy_private_key_input, width=3)
        self.copy_priv_key_btn.pack(pady=2)

        # Private key file load
        key_file_frame = ttk.Frame(key_frame)
        key_file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(key_file_frame, text="Load Private Key from File",
                  command=self.load_private_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_file_frame, text="Paste from Key Generation",
                  command=self.paste_private_key).pack(side=tk.LEFT, padx=5)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill=tk.X, pady=10)
        ttk.Button(button_frame, text="🔓 Decrypt", command=self.decrypt,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Output section - Make it expandable
        output_frame = ttk.LabelFrame(main_container, text="Decryption Result", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True)

        # Performance metrics frame
        metrics_frame = ttk.LabelFrame(output_frame, text="Performance Metrics", padding="10")
        metrics_frame.pack(fill=tk.X, pady=(0, 10))

        # Create metrics display
        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=4, width=80)
        self.metrics_text.pack(fill=tk.X)

        # Decrypted output with better layout
        decrypted_container = ttk.LabelFrame(output_frame, text="Decrypted Data", padding="10")
        decrypted_container.pack(fill=tk.BOTH, expand=True)

        # Decrypted text with copy button
        decrypted_text_frame = ttk.Frame(decrypted_container)
        decrypted_text_frame.pack(fill=tk.BOTH, expand=True)

        self.decrypted_output = scrolledtext.ScrolledText(decrypted_text_frame, height=10, width=80)
        self.decrypted_output.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Copy button for decrypted text
        copy_btn_frame = ttk.Frame(decrypted_text_frame)
        copy_btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        self.copy_decrypted_btn = ttk.Button(copy_btn_frame, text="📋 Copy",
                                           command=self.copy_decrypted, state='disabled',
                                           width=8)
        self.copy_decrypted_btn.pack(pady=2)
        self.save_decrypted_btn = ttk.Button(copy_btn_frame, text="💾 Save",
                                           command=self.save_decrypted, state='disabled',
                                           width=8)
        self.save_decrypted_btn.pack(pady=2)

    def copy_ciphertext_input(self):
        """Copy ciphertext input to clipboard"""
        ciphertext = self.ciphertext_input.get(1.0, tk.END).strip()
        if ciphertext:
            self.frame.clipboard_clear()
            self.frame.clipboard_append(ciphertext)
            self.frame.update()
            messagebox.showinfo("Copied", "Ciphertext copied to clipboard")

    def copy_private_key_input(self):
        """Copy private key input to clipboard"""
        private_key = self.private_key_input.get(1.0, tk.END).strip()
        if private_key:
            self.frame.clipboard_clear()
            self.frame.clipboard_append(private_key)
            self.frame.update()
            messagebox.showinfo("Copied", "Private key copied to clipboard")

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
                self.update_ciphertext_info()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load ciphertext: {str(e)}")

    def update_ciphertext_info(self):
        """Update ciphertext information display"""
        ciphertext = self.ciphertext_input.get(1.0, tk.END).strip()
        if ciphertext:
            ciphertext_size = len(ciphertext)
            self.ciphertext_info_label.config(
                text=f"Ciphertext size: {ciphertext_size:,} characters"
            )
        else:
            self.ciphertext_info_label.config(text="")

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

            # Get key info
            key_info = self.rsa_handler.get_key_info(private_key_pem)
            key_size = key_info['key_size']
            ciphertext_size = len(ciphertext_b64)

            # Perform decryption with timing
            start_time = time.perf_counter()
            decrypted_data = self.rsa_handler.decrypt(ciphertext_b64, private_key_pem)
            end_time = time.perf_counter()

            decryption_time = (end_time - start_time) * 1000  # Convert to milliseconds
            decrypted_size = len(decrypted_data)

            # Try to decode as text, otherwise show as hex
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                is_text = True
                data_type = "Text"
                display_text = decrypted_text
            except:
                decrypted_text = decrypted_data.hex()
                is_text = False
                data_type = "Binary"
                display_text = decrypted_text

            # Display performance metrics
            self.metrics_text.delete(1.0, tk.END)
            self.metrics_text.insert(tk.END, "🔓 DECRYPTION METRICS\n")
            self.metrics_text.insert(tk.END, "=" * 40 + "\n")
            self.metrics_text.insert(tk.END, f"Data Type: {data_type}\n")
            self.metrics_text.insert(tk.END, f"Key Size: {key_size} bits\n")
            self.metrics_text.insert(tk.END, f"Ciphertext Size: {ciphertext_size:,} characters\n")
            self.metrics_text.insert(tk.END, f"Decrypted Size: {decrypted_size:,} bytes\n")
            self.metrics_text.insert(tk.END, f"Decryption Time: {decryption_time:.2f} ms\n")

            if is_text:
                self.metrics_text.insert(tk.END, f"Text Length: {len(decrypted_text)} characters\n")
            else:
                self.metrics_text.insert(tk.END, f"Hex Length: {len(decrypted_text)} characters\n")

            # Display decrypted data
            self.decrypted_output.delete(1.0, tk.END)
            self.decrypted_output.insert(tk.END, display_text)

            self.last_decrypted_data = decrypted_data
            self.last_is_text = is_text
            self.copy_decrypted_btn.config(state='normal')
            self.save_decrypted_btn.config(state='normal')

            if self.status_var:
                self.status_var.set(f"RSA decryption completed in {decryption_time:.2f} ms")

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
        self.ciphertext_info_label.config(text="")
        self.private_key_input.delete(1.0, tk.END)
        self.decrypted_output.delete(1.0, tk.END)
        self.metrics_text.delete(1.0, tk.END)
        self.copy_decrypted_btn.config(state='disabled')
        self.save_decrypted_btn.config(state='disabled')