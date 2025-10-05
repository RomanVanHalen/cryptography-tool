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

        # Main container with better spacing
        main_container = ttk.Frame(self.frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Key generation settings
        settings_frame = ttk.LabelFrame(main_container, text="RSA Key Generation Settings", padding="15")
        settings_frame.pack(fill=tk.X, pady=(0, 10))

        # Key size selection - USING PACK
        key_size_frame = ttk.Frame(settings_frame)
        key_size_frame.pack(fill=tk.X, pady=5)

        ttk.Label(key_size_frame, text="Key Size:").pack(side=tk.LEFT)
        key_size_radio_frame = ttk.Frame(key_size_frame)
        key_size_radio_frame.pack(side=tk.LEFT, padx=10)

        self.key_size_var = tk.StringVar(value="2048")
        ttk.Radiobutton(key_size_radio_frame, text="1024-bit", variable=self.key_size_var,
                       value="1024").pack(side=tk.LEFT)
        ttk.Radiobutton(key_size_radio_frame, text="2048-bit", variable=self.key_size_var,
                       value="2048").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(key_size_radio_frame, text="4096-bit", variable=self.key_size_var,
                       value="4096").pack(side=tk.LEFT)

        # Public exponent - USING PACK
        public_exp_frame = ttk.Frame(settings_frame)
        public_exp_frame.pack(fill=tk.X, pady=5)

        ttk.Label(public_exp_frame, text="Public Exponent:").pack(side=tk.LEFT)
        self.public_exp_var = tk.StringVar(value="65537")
        ttk.Entry(public_exp_frame, textvariable=self.public_exp_var, width=15).pack(side=tk.LEFT, padx=10)

        # Key ID (optional) - USING PACK
        key_id_frame = ttk.Frame(settings_frame)
        key_id_frame.pack(fill=tk.X, pady=5)

        ttk.Label(key_id_frame, text="Key ID (optional):").pack(side=tk.LEFT)
        self.key_id_var = tk.StringVar()
        ttk.Entry(key_id_frame, textvariable=self.key_id_var, width=30).pack(side=tk.LEFT, padx=10)

        # Action buttons
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill=tk.X, pady=10)
        ttk.Button(button_frame, text="🔑 Generate RSA Keys", command=self.generate_keys,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Results section
        results_frame = ttk.LabelFrame(main_container, text="Generated RSA Keys", padding="15")
        results_frame.pack(fill=tk.BOTH, expand=True)

        # Performance metrics - FIXED: Reduced height
        metrics_frame = ttk.LabelFrame(results_frame, text="Key Generation Metrics", padding="10")
        metrics_frame.pack(fill=tk.X, pady=(0, 10))

        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=3, width=80)  # Reduced height
        self.metrics_text.pack(fill=tk.X)

        # Keys container for side-by-side layout
        keys_container = ttk.Frame(results_frame)
        keys_container.pack(fill=tk.BOTH, expand=True, pady=5)

        # Public key section - LEFT SIDE
        public_key_frame = ttk.LabelFrame(keys_container, text="Public Key", padding="10")
        public_key_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Public key header with copy button
        pub_key_header = ttk.Frame(public_key_frame)
        pub_key_header.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(pub_key_header, text="PEM Format:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT)

        pub_key_actions = ttk.Frame(pub_key_header)
        pub_key_actions.pack(side=tk.RIGHT)

        self.copy_pub_btn = ttk.Button(pub_key_actions, text="📋 Copy",
                                      command=self.copy_public_key, state='disabled',
                                      width=10)
        self.copy_pub_btn.pack(side=tk.LEFT, padx=2)
        self.save_pub_btn = ttk.Button(pub_key_actions, text="💾 Save",
                                      command=self.save_public_key, state='disabled',
                                      width=10)
        self.save_pub_btn.pack(side=tk.LEFT, padx=2)

        # Public key text area
        self.public_key_text = scrolledtext.ScrolledText(public_key_frame, height=10, width=40)
        self.public_key_text.pack(fill=tk.BOTH, expand=True)

        # Private key section - RIGHT SIDE
        private_key_frame = ttk.LabelFrame(keys_container, text="Private Key", padding="10")
        private_key_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # Private key header with copy button
        priv_key_header = ttk.Frame(private_key_frame)
        priv_key_header.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(priv_key_header, text="PEM Format:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT)

        priv_key_actions = ttk.Frame(priv_key_header)
        priv_key_actions.pack(side=tk.RIGHT)

        self.copy_priv_btn = ttk.Button(priv_key_actions, text="📋 Copy",
                                       command=self.copy_private_key, state='disabled',
                                       width=10)
        self.copy_priv_btn.pack(side=tk.LEFT, padx=2)
        self.save_priv_btn = ttk.Button(priv_key_actions, text="💾 Save",
                                       command=self.save_private_key, state='disabled',
                                       width=10)
        self.save_priv_btn.pack(side=tk.LEFT, padx=2)

        # Private key text area
        self.private_key_text = scrolledtext.ScrolledText(private_key_frame, height=10, width=40)
        self.private_key_text.pack(fill=tk.BOTH, expand=True)

        # Additional key info at bottom
        key_info_frame = ttk.LabelFrame(results_frame, text="Key Information", padding="10")
        key_info_frame.pack(fill=tk.X, pady=(10, 0))

        self.key_info_text = scrolledtext.ScrolledText(key_info_frame, height=3, width=80)
        self.key_info_text.pack(fill=tk.X)

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
            self.public_key_text.see(1.0)  # Auto-scroll to top

            self.private_key_text.delete(1.0, tk.END)
            self.private_key_text.insert(tk.END, keys['private_key_pem'])
            self.private_key_text.see(1.0)  # Auto-scroll to top

            # Display performance metrics
            self.metrics_text.delete(1.0, tk.END)
            self.metrics_text.insert(tk.END, "🔑 KEY GENERATION METRICS\n")
            self.metrics_text.insert(tk.END, "=" * 40 + "\n")
            self.metrics_text.insert(tk.END, f"Key ID: {key_id}\n")
            self.metrics_text.insert(tk.END, f"Key Size: {key_size} bits\n")
            self.metrics_text.insert(tk.END, f"Public Exponent: {public_exp}\n")
            self.metrics_text.insert(tk.END, f"Generation Time: {generation_time:.3f} seconds\n")

            # Display key information
            self.key_info_text.delete(1.0, tk.END)
            self.key_info_text.insert(tk.END, "🔍 KEY INFORMATION\n")
            self.key_info_text.insert(tk.END, "=" * 40 + "\n")
            self.key_info_text.insert(tk.END, f"Modulus (first 64 chars): {keys['modulus_hex'][:64]}...\n")
            self.key_info_text.insert(tk.END, f"Public Exponent (e): {keys['public_exponent_value']}\n")
            self.key_info_text.insert(tk.END, f"Modulus Bit Length: {keys['key_size']} bits\n")

            self.last_keys = keys
            self.key_id = key_id

            # Enable buttons
            self.copy_pub_btn.config(state='normal')
            self.save_pub_btn.config(state='normal')
            self.copy_priv_btn.config(state='normal')
            self.save_priv_btn.config(state='normal')

            if self.status_var:
                self.status_var.set(f"RSA keys generated in {generation_time:.3f} seconds")

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
        self.metrics_text.delete(1.0, tk.END)
        self.key_info_text.delete(1.0, tk.END)
        self.copy_pub_btn.config(state='disabled')
        self.save_pub_btn.config(state='disabled')
        self.copy_priv_btn.config(state='disabled')
        self.save_priv_btn.config(state='disabled')