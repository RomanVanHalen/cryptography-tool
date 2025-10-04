"""
RSA Key Generation tab
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
from crypto.rsa_handler import RSAHandler


class KeyGenerationTab:
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
        """Create the key generation tab interface"""
        self.frame = ttk.Frame(self.parent)

        # Key generation settings
        settings_frame = ttk.LabelFrame(self.frame, text="RSA Key Generation Settings", padding="15")
        settings_frame.pack(fill=tk.X, padx=10, pady=10)

        # Key size selection
        ttk.Label(settings_frame, text="Key Size:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.key_size_var = tk.StringVar(value="2048")
        key_size_frame = ttk.Frame(settings_frame)
        key_size_frame.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(key_size_frame, text="1024-bit", variable=self.key_size_var,
                        value="1024").pack(side=tk.LEFT)
        ttk.Radiobutton(key_size_frame, text="2048-bit", variable=self.key_size_var,
                        value="2048").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(key_size_frame, text="4096-bit", variable=self.key_size_var,
                        value="4096").pack(side=tk.LEFT)

        # Public exponent
        ttk.Label(settings_frame, text="Public Exponent:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.public_exp_var = tk.StringVar(value="65537")
        ttk.Entry(settings_frame, textvariable=self.public_exp_var, width=15).grid(row=1, column=1, sticky=tk.W, padx=5)

        # Key ID (optional)
        ttk.Label(settings_frame, text="Key ID (optional):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.key_id_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.key_id_var, width=30).grid(row=2, column=1, sticky=tk.W, padx=5)

        # Action buttons
        button_frame = ttk.Frame(settings_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Generate RSA Keys", command=self.generate_keys,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Results section
        results_frame = ttk.LabelFrame(self.frame, text="Generated RSA Keys", padding="15")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Public key
        ttk.Label(results_frame, text="Public Key:").pack(anchor=tk.W)
        self.public_key_text = scrolledtext.ScrolledText(results_frame, height=6, width=80)
        self.public_key_text.pack(fill=tk.X, pady=5)

        # Public key actions
        pub_key_actions = ttk.Frame(results_frame)
        pub_key_actions.pack(fill=tk.X, pady=5)
        self.copy_pub_btn = ttk.Button(pub_key_actions, text="Copy Public Key",
                                       command=self.copy_public_key, state='disabled')
        self.copy_pub_btn.pack(side=tk.LEFT, padx=5)
        self.save_pub_btn = ttk.Button(pub_key_actions, text="Save Public Key",
                                       command=self.save_public_key, state='disabled')
        self.save_pub_btn.pack(side=tk.LEFT, padx=5)

        # Private key
        ttk.Label(results_frame, text="Private Key:").pack(anchor=tk.W, pady=(10, 0))
        self.private_key_text = scrolledtext.ScrolledText(results_frame, height=8, width=80)
        self.private_key_text.pack(fill=tk.X, pady=5)

        # Private key actions
        priv_key_actions = ttk.Frame(results_frame)
        priv_key_actions.pack(fill=tk.X, pady=5)
        self.copy_priv_btn = ttk.Button(priv_key_actions, text="Copy Private Key",
                                        command=self.copy_private_key, state='disabled')
        self.copy_priv_btn.pack(side=tk.LEFT, padx=5)
        self.save_priv_btn = ttk.Button(priv_key_actions, text="Save Private Key",
                                        command=self.save_private_key, state='disabled')
        self.save_priv_btn.pack(side=tk.LEFT, padx=5)

        # Key information
        self.info_frame = ttk.LabelFrame(results_frame, text="Key Information", padding="10")
        self.info_frame.pack(fill=tk.X, pady=10)

        self.info_text = scrolledtext.ScrolledText(self.info_frame, height=4, width=80)
        self.info_text.pack(fill=tk.X)

    def generate_keys(self):
        """Generate RSA key pair"""
        try:
            if self.status_var:
                self.status_var.set("Generating RSA keys...")

            key_size = int(self.key_size_var.get())
            public_exp = int(self.public_exp_var.get())
            key_id = self.key_id_var.get().strip() or f"rsa_key_{int(time.time())}"

            start_time = time.perf_counter()
            keys = self.rsa_handler.generate_key_pair(key_size, public_exp)
            end_time = time.perf_counter()

            generation_time = end_time - start_time

            # Display keys
            self.public_key_text.delete(1.0, tk.END)
            self.public_key_text.insert(tk.END, keys['public_key_pem'])

            self.private_key_text.delete(1.0, tk.END)
            self.private_key_text.insert(tk.END, keys['private_key_pem'])

            # Display key information
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, f"Key ID: {key_id}\n")
            self.info_text.insert(tk.END, f"Key Size: {key_size} bits\n")
            self.info_text.insert(tk.END, f"Public Exponent: {public_exp}\n")
            self.info_text.insert(tk.END, f"Generation Time: {generation_time:.2f} seconds\n")
            self.info_text.insert(tk.END, f"Modulus (n): {keys['modulus_hex'][:64]}...\n")
            self.info_text.insert(tk.END, f"Public Exponent (e): {keys['public_exponent']}\n")

            self.last_keys = keys
            self.key_id = key_id

            # Enable buttons
            self.copy_pub_btn.config(state='normal')
            self.save_pub_btn.config(state='normal')
            self.copy_priv_btn.config(state='normal')
            self.save_priv_btn.config(state='normal')

            if self.status_var:
                self.status_var.set("RSA keys generated successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
            if self.status_var:
                self.status_var.set("Key generation failed")

    def copy_public_key(self):
        """Copy public key to clipboard"""
        if hasattr(self, 'last_keys'):
            self.frame.clipboard_clear()
            self.frame.clipboard_append(self.last_keys['public_key_pem'])
            self.frame.update()
            messagebox.showinfo("Copied", "Public key copied to clipboard")

    def copy_private_key(self):
        """Copy private key to clipboard"""
        if hasattr(self, 'last_keys'):
            self.frame.clipboard_clear()
            self.frame.clipboard_append(self.last_keys['private_key_pem'])
            self.frame.update()
            messagebox.showinfo("Copied", "Private key copied to clipboard")

    def save_public_key(self):
        """Save public key to file"""
        if not hasattr(self, 'last_keys'):
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile=f"{self.key_id}_public.pem"
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.last_keys['public_key_pem'])
                messagebox.showinfo("Success", f"Public key saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save public key: {str(e)}")

    def save_private_key(self):
        """Save private key to file"""
        if not hasattr(self, 'last_keys'):
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile=f"{self.key_id}_private.pem"
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.last_keys['private_key_pem'])
                messagebox.showinfo("Success", f"Private key saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save private key: {str(e)}")

    def clear(self):
        """Clear all outputs"""
        self.public_key_text.delete(1.0, tk.END)
        self.private_key_text.delete(1.0, tk.END)
        self.info_text.delete(1.0, tk.END)
        self.copy_pub_btn.config(state='disabled')
        self.save_pub_btn.config(state='disabled')
        self.copy_priv_btn.config(state='disabled')
        self.save_priv_btn.config(state='disabled')