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

        # Main container with better spacing
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Input section - Fixed height to prevent compression
        input_frame = ttk.LabelFrame(main_container, text="RSA Encryption Input", padding="15")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # Input type
        input_type_frame = ttk.Frame(input_frame)
        input_type_frame.pack(fill=tk.X, pady=5)

        ttk.Label(input_type_frame, text="Input Type:").pack(side=tk.LEFT)
        self.input_var = tk.StringVar(value="text")
        ttk.Radiobutton(input_type_frame, text="Text", variable=self.input_var,
                        value="text").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(input_type_frame, text="File", variable=self.input_var,
                        value="file").pack(side=tk.LEFT)

        # Text input with copy button
        self.text_frame = ttk.Frame(input_frame)
        self.text_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.text_frame, text="Text to Encrypt:").pack(anchor=tk.W)

        text_input_container = ttk.Frame(self.text_frame)
        text_input_container.pack(fill=tk.X, pady=5)

        self.text_input = scrolledtext.ScrolledText(text_input_container, height=4, width=80)
        self.text_input.pack(fill=tk.X, side=tk.LEFT, expand=True)

        # Text copy button
        text_copy_frame = ttk.Frame(text_input_container)
        text_copy_frame.pack(side=tk.RIGHT, padx=(5, 0))
        self.copy_text_btn = ttk.Button(text_copy_frame, text="📋",
                                       command=self.copy_text_input, width=3)
        self.copy_text_btn.pack(pady=2)

        # File input
        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.file_frame, text="File to Encrypt:").pack(anchor=tk.W)
        file_select_frame = ttk.Frame(self.file_frame)
        file_select_frame.pack(fill=tk.X, pady=5)
        self.file_path = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)

        # File info display
        self.file_info_label = ttk.Label(self.file_frame, text="", foreground="gray")
        self.file_info_label.pack(anchor=tk.W)

        # Public key input with copy button
        key_frame = ttk.Frame(input_frame)
        key_frame.pack(fill=tk.X, pady=10)
        ttk.Label(key_frame, text="Public Key (PEM format):").pack(anchor=tk.W)

        public_key_container = ttk.Frame(key_frame)
        public_key_container.pack(fill=tk.X, pady=5)

        self.public_key_input = scrolledtext.ScrolledText(public_key_container, height=4, width=80)  # Reduced height
        self.public_key_input.pack(fill=tk.X, side=tk.LEFT, expand=True)

        # Public key copy button
        pub_key_copy_frame = ttk.Frame(public_key_container)
        pub_key_copy_frame.pack(side=tk.RIGHT, padx=(5, 0))
        self.copy_pub_key_btn = ttk.Button(pub_key_copy_frame, text="📋",
                                          command=self.copy_public_key_input, width=3)
        self.copy_pub_key_btn.pack(pady=2)

        # Public key file load
        key_file_frame = ttk.Frame(key_frame)
        key_file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(key_file_frame, text="Load Public Key from File",
                  command=self.load_public_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_file_frame, text="Paste from Key Generation",
                  command=self.paste_public_key).pack(side=tk.LEFT, padx=5)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill=tk.X, pady=10)
        ttk.Button(button_frame, text="🔒 Encrypt", command=self.encrypt,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Output section - FIXED: Give more space to ciphertext
        output_frame = ttk.LabelFrame(main_container, text="Encryption Result", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True)

        # Performance metrics frame - FIXED: Reduced height
        metrics_frame = ttk.LabelFrame(output_frame, text="Performance Metrics", padding="10")
        metrics_frame.pack(fill=tk.X, pady=(0, 10))

        # Create metrics display - FIXED: Smaller height
        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=3, width=80)  # Reduced from 5 to 3
        self.metrics_text.pack(fill=tk.X)

        # Ciphertext output - FIXED: More space allocated
        ciphertext_container = ttk.LabelFrame(output_frame, text="Ciphertext (Base64)", padding="10")
        ciphertext_container.pack(fill=tk.BOTH, expand=True)

        # Ciphertext with copy button - FIXED: Better layout
        ciphertext_main_frame = ttk.Frame(ciphertext_container)
        ciphertext_main_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Left side: Ciphertext area
        ciphertext_left_frame = ttk.Frame(ciphertext_main_frame)
        ciphertext_left_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        ttk.Label(ciphertext_left_frame, text="Encrypted Result:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)

        self.ciphertext_output = scrolledtext.ScrolledText(ciphertext_left_frame, height=12, width=80)  # Increased height
        self.ciphertext_output.pack(fill=tk.BOTH, expand=True, pady=5)

        # Right side: Action buttons
        cipher_btn_frame = ttk.Frame(ciphertext_main_frame)
        cipher_btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))

        ttk.Label(cipher_btn_frame, text="Actions:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))

        self.copy_cipher_btn = ttk.Button(cipher_btn_frame, text="📋 Copy Ciphertext",
                                         command=self.copy_ciphertext, state='disabled',
                                         width=15)
        self.copy_cipher_btn.pack(pady=5, fill=tk.X)

        self.save_cipher_btn = ttk.Button(cipher_btn_frame, text="💾 Save to File",
                                         command=self.save_ciphertext, state='disabled',
                                         width=15)
        self.save_cipher_btn.pack(pady=5, fill=tk.X)

        # Initialize
        self.toggle_input()
        self.input_var.trace('w', lambda *args: self.toggle_input())

    def copy_text_input(self):
        """Copy text input to clipboard"""
        text = self.text_input.get(1.0, tk.END).strip()
        if text:
            self.frame.clipboard_clear()
            self.frame.clipboard_append(text)
            self.frame.update()
            messagebox.showinfo("Copied", "Text copied to clipboard")

    def copy_public_key_input(self):
        """Copy public key input to clipboard"""
        public_key = self.public_key_input.get(1.0, tk.END).strip()
        if public_key:
            self.frame.clipboard_clear()
            self.frame.clipboard_append(public_key)
            self.frame.update()
            messagebox.showinfo("Copied", "Public key copied to clipboard")

    def toggle_input(self):
        """Toggle between text and file input"""
        if self.input_var.get() == "text":
            self.text_frame.pack()
            self.file_frame.pack_forget()
        else:
            self.text_frame.pack_forget()
            self.file_frame.pack()
            self.update_file_info()

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            self.update_file_info()

    def update_file_info(self):
        """Update file information display"""
        filepath = self.file_path.get()
        if filepath and os.path.exists(filepath):
            file_size = os.path.getsize(filepath)
            file_size_kb = file_size / 1024
            self.file_info_label.config(
                text=f"File: {os.path.basename(filepath)} | Size: {file_size:,} bytes ({file_size_kb:.2f} KB)"
            )
        else:
            self.file_info_label.config(text="")

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

            # Get key info
            key_info = self.rsa_handler.get_key_info(public_key_pem)
            key_size = key_info['key_size']
            max_size = self.rsa_handler.get_max_encryption_size(key_size)

            # Get data to encrypt
            if self.input_var.get() == "text":
                plaintext = self.text_input.get(1.0, tk.END).strip()
                if not plaintext:
                    messagebox.showerror("Error", "Please enter text to encrypt")
                    return

                input_type = "text"
                input_data = plaintext.encode('utf-8')
                input_size = len(input_data)
                input_info = f"Text length: {len(plaintext)} characters"

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
                input_info = f"File: {filename}"

            # Check input size limit
            if input_size > max_size:
                messagebox.showerror("Error",
                    f"Input too large for RSA encryption.\n"
                    f"Maximum for {key_size}-bit key: {max_size:,} bytes\n"
                    f"Your input: {input_size:,} bytes\n\n"
                    f"Consider using hybrid encryption (RSA + AES) for large files.")
                return

            # Perform encryption with timing
            start_time = time.perf_counter()
            ciphertext_b64 = self.rsa_handler.encrypt(input_data, public_key_pem)
            end_time = time.perf_counter()

            encryption_time = (end_time - start_time) * 1000  # Convert to milliseconds
            ciphertext_size = len(ciphertext_b64)

            # Display performance metrics
            self.metrics_text.delete(1.0, tk.END)
            self.metrics_text.insert(tk.END, "🔒 ENCRYPTION METRICS\n")
            self.metrics_text.insert(tk.END, "=" * 40 + "\n")
            self.metrics_text.insert(tk.END, f"Input Type: {input_type}\n")
            self.metrics_text.insert(tk.END, f"{input_info}\n")
            self.metrics_text.insert(tk.END, f"Input Size: {input_size:,} bytes\n")
            self.metrics_text.insert(tk.END, f"Key Size: {key_size} bits\n")
            self.metrics_text.insert(tk.END, f"Max RSA Input: {max_size:,} bytes\n")
            self.metrics_text.insert(tk.END, f"Encryption Time: {encryption_time:.2f} ms\n")
            self.metrics_text.insert(tk.END, f"Ciphertext Size: {ciphertext_size:,} characters\n")
            self.metrics_text.insert(tk.END, f"Size Increase: {((ciphertext_size/input_size)-1)*100:+.1f}%\n")

            # Display ciphertext - FIXED: Clear and insert with highlighting
            self.ciphertext_output.delete(1.0, tk.END)
            self.ciphertext_output.insert(tk.END, ciphertext_b64)

            # Auto-scroll to top
            self.ciphertext_output.see(1.0)

            self.last_ciphertext = ciphertext_b64
            self.copy_cipher_btn.config(state='normal')
            self.save_cipher_btn.config(state='normal')

            if self.status_var:
                self.status_var.set(f"RSA encryption completed in {encryption_time:.2f} ms")

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
        self.file_info_label.config(text="")
        self.public_key_input.delete(1.0, tk.END)
        self.ciphertext_output.delete(1.0, tk.END)
        self.metrics_text.delete(1.0, tk.END)
        self.copy_cipher_btn.config(state='disabled')
        self.save_cipher_btn.config(state='disabled')