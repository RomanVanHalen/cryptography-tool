"""
AES Decryption tab implementation
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from crypto.aes_handler import AESHandler


class AESDecryptionTab:
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
        """Create the decryption tab interface"""
        self.frame = ttk.Frame(self.parent)

        # Input section
        input_frame = ttk.LabelFrame(self.frame, text="AES Decryption Settings", padding="15")
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        # Input method
        ttk.Label(input_frame, text="Input Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_var = tk.StringVar(value="file")
        ttk.Radiobutton(input_frame, text="Encrypted File", variable=self.input_var,
                        value="file").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(input_frame, text="Ciphertext", variable=self.input_var,
                        value="ciphertext").grid(row=0, column=2, sticky=tk.W)

        # File input for decryption
        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.file_frame, text="Encrypted File:").pack(anchor=tk.W)
        file_select_frame = ttk.Frame(self.file_frame)
        file_select_frame.pack(fill=tk.X, pady=5)
        self.file_path = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)

        # Ciphertext input
        self.ciphertext_frame = ttk.Frame(input_frame)
        self.ciphertext_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.ciphertext_frame, text="Ciphertext (hex):").pack(anchor=tk.W)
        self.ciphertext_input = scrolledtext.ScrolledText(self.ciphertext_frame, height=4, width=80)
        self.ciphertext_input.pack(fill=tk.X, pady=5)

        # AES-specific decryption settings
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

        # Encryption mode
        ttk.Label(settings_frame, text="Encryption Mode:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.mode_combo = ttk.Combobox(settings_frame, values=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
                                       state="readonly", width=15)
        self.mode_combo.set('CBC')
        self.mode_combo.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        # IV/Nonce input
        ttk.Label(settings_frame, text="IV/Nonce (hex):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.iv_entry = ttk.Entry(settings_frame, width=40, font=('Arial', 10))
        self.iv_entry.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(settings_frame, text="(Required for CBC, CFB, OFB, CTR modes)").grid(row=3, column=2, sticky=tk.W,
                                                                                       padx=10)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Decrypt", command=self.process_decryption,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Output section
        output_frame = ttk.LabelFrame(self.frame, text="AES Decryption Results", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Download button
        self.download_btn = ttk.Button(output_frame, text="Download Decrypted File",
                                       command=self.download_result, state='disabled')
        self.download_btn.pack(pady=5)

        # Initialize
        self.toggle_input()
        self.input_var.trace('w', lambda *args: self.toggle_input())

    def toggle_input(self):
        """Toggle between file and ciphertext input"""
        if self.input_var.get() == "file":
            self.file_frame.grid()
            self.ciphertext_frame.grid_remove()
        else:
            self.file_frame.grid_remove()
            self.ciphertext_frame.grid()

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def process_decryption(self):
        """Handle AES decryption process"""
        try:
            if self.status_var:
                self.status_var.set("Processing AES decryption...")

            if self.input_var.get() == "file":
                filepath = self.file_path.get()
                if not filepath or not os.path.exists(filepath):
                    messagebox.showerror("Error", "Please select a valid encrypted file")
                    return

                with open(filepath, 'rb') as f:
                    file_data = f.read()

                mode = self.mode_combo.get()
                iv_hex = self.iv_entry.get().strip()

                # Extract IV/Nonce from file data based on mode
                if mode.upper() in ['CBC', 'CFB', 'OFB'] and len(file_data) >= 16:  # AES uses 16-byte IV
                    iv_nonce = file_data[:16]
                    ciphertext = file_data[16:]
                elif mode.upper() == 'CTR' and len(file_data) >= 8:  # AES CTR uses 8-byte nonce
                    iv_nonce = file_data[:8]
                    ciphertext = file_data[8:]
                else:
                    ciphertext = file_data
                    iv_nonce = bytes.fromhex(iv_hex) if iv_hex else None

            else:
                ciphertext_hex = self.ciphertext_input.get(1.0, tk.END).strip()
                if not ciphertext_hex:
                    messagebox.showerror("Error", "Please enter ciphertext in hex format")
                    return
                ciphertext = bytes.fromhex(ciphertext_hex)
                iv_hex = self.iv_entry.get().strip()
                iv_nonce = bytes.fromhex(iv_hex) if iv_hex else None
                mode = self.mode_combo.get()

            key_str = self.key_entry.get().strip()
            key_size = int(self.key_size_var.get())
            required_length = key_size // 8

            if len(key_str) != required_length:
                messagebox.showerror("Error",
                                     f"AES-{key_size} key must be exactly {required_length} characters")
                return

            # Validate IV/Nonce for modes that require it
            if mode.upper() in ['CBC', 'CFB', 'OFB']:
                if not iv_nonce or len(iv_nonce) != 16:
                    messagebox.showerror("Error", "IV must be 16 bytes (32 hex characters) for this mode")
                    return
            elif mode.upper() == 'CTR':
                if not iv_nonce or len(iv_nonce) != 8:
                    messagebox.showerror("Error", "Nonce must be 8 bytes (16 hex characters) for CTR mode")
                    return

            result = self.aes_handler.decrypt(ciphertext, key_str.encode('utf-8'), iv_nonce, mode, key_size)
            self.display_results(result)
            self.last_result = result
            self.download_btn.config(state='normal')

            if self.status_var:
                self.status_var.set("AES decryption completed successfully")

        except Exception as e:
            messagebox.showerror("Error", f"AES decryption failed: {str(e)}")
            if self.status_var:
                self.status_var.set("AES decryption failed")

    def display_results(self, result):
        """Display decryption results"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "AES DECRYPTION SUCCESSFUL\n")
        self.output_text.insert(tk.END, "=" * 50 + "\n\n")
        self.output_text.insert(tk.END, f"Key Size: AES-{result['key_size']}\n")
        self.output_text.insert(tk.END, f"Mode: {result['mode']}\n")
        self.output_text.insert(tk.END, f"Decryption Time: {result['time'] * 1000:.3f} ms\n")
        self.output_text.insert(tk.END, f"Decrypted Size: {result['decrypted_size']} bytes\n\n")

        try:
            decoded = result['plaintext'].decode('utf-8')
            self.output_text.insert(tk.END, f"Decrypted Text:\n{decoded}\n")
        except:
            self.output_text.insert(tk.END, "Decrypted data is binary (likely a file)\n")

    def download_result(self):
        """Download decryption result"""
        if not hasattr(self, 'last_result'):
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".bin",
            filetypes=[("All files", "*.*"), ("PDF files", "*.pdf"), ("Text files", "*.txt")]
        )

        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self.last_result['plaintext'])

                # Try to open the file if it's a PDF
                if filename.lower().endswith('.pdf'):
                    self.try_open_file(filename)

                messagebox.showinfo("Success", f"Decrypted file saved as {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save decrypted file: {str(e)}")

    def try_open_file(self, filename):
        """Try to open the decrypted file if it's a PDF"""
        try:
            import subprocess
            import sys
            import os
            if os.name == 'nt':  # Windows
                os.startfile(filename)
            elif sys.platform == "darwin":  # macOS
                subprocess.Popen(["open", filename])
            else:  # Linux
                subprocess.Popen(["xdg-open", filename])
        except Exception as e:
            messagebox.showwarning("Warning", f"File saved but could not be opened automatically.\n{e}")

    def clear(self):
        """Clear inputs/outputs"""
        self.file_path.set("")
        self.ciphertext_input.delete(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.download_btn.config(state='disabled')