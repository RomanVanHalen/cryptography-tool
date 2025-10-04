# des_crypto_tool.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import time
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter


class DESCryptoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("DES Cryptography Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg='white')

        # Clean, professional colors
        self.colors = {
            'bg': 'white',
            'fg': '#333333',
            'accent': '#2563EB',
            'button_bg': '#2563EB',
            'button_fg': 'white',
            'group_bg': '#F8FAFC',
            'border': '#E2E8F0'
        }

        self.setup_styles()
        self.create_main_interface()

    def setup_styles(self):
        """Configure clean, professional styles"""
        style = ttk.Style()
        style.theme_use('clam')

        # Configure styles
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure('TLabelframe', background=self.colors['group_bg'], bordercolor=self.colors['border'])
        style.configure('TLabelframe.Label', background=self.colors['group_bg'], foreground=self.colors['fg'])

        style.configure('Accent.TButton', background=self.colors['button_bg'], foreground=self.colors['button_fg'])
        style.configure('Secondary.TButton', background='#64748B', foreground='white')

        style.configure('TNotebook', background=self.colors['bg'])
        style.configure('TNotebook.Tab', background='#E2E8F0', padding=[15, 5])
        style.map('TNotebook.Tab', background=[('selected', self.colors['accent'])],
                  foreground=[('selected', 'white')])

    def create_main_interface(self):
        """Create the main application interface"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="DES Cryptography Tool",
                                font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 10))

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs
        self.encryption_tab = self.create_encryption_tab()
        self.decryption_tab = self.create_decryption_tab()

        self.notebook.add(self.encryption_tab, text="Encryption")
        self.notebook.add(self.decryption_tab, text="Decryption")

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var)
        status_bar.pack(fill=tk.X, pady=(10, 0))

    def create_encryption_tab(self):
        """Create the encryption tab"""
        tab = ttk.Frame(self.notebook)

        # Input section
        input_frame = ttk.LabelFrame(tab, text="Encryption Settings", padding="15")
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        # Input method
        ttk.Label(input_frame, text="Input Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.encrypt_input_var = tk.StringVar(value="text")
        ttk.Radiobutton(input_frame, text="Text", variable=self.encrypt_input_var,
                        value="text").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(input_frame, text="File", variable=self.encrypt_input_var,
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
        ttk.Button(file_select_frame, text="Browse", command=self.browse_encrypt_file).pack(side=tk.LEFT)

        # Encryption settings
        settings_frame = ttk.Frame(input_frame)
        settings_frame.grid(row=3, column=0, columnspan=3, sticky=tk.W + tk.E, pady=10)

        ttk.Label(settings_frame, text="DES Key (8 characters):").grid(row=0, column=0, sticky=tk.W)
        self.encrypt_key = ttk.Entry(settings_frame, width=20, font=('Arial', 10))
        self.encrypt_key.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.encrypt_key.insert(0, "8bytekey")

        ttk.Label(settings_frame, text="Encryption Mode:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.encrypt_mode = ttk.Combobox(settings_frame, values=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
                                         state="readonly", width=15)
        self.encrypt_mode.set('CBC')
        self.encrypt_mode.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Encrypt", command=self.process_encryption,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_encryption).pack(side=tk.LEFT, padx=5)

        # Output section
        output_frame = ttk.LabelFrame(tab, text="Encryption Results", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.encrypt_output = scrolledtext.ScrolledText(output_frame, height=8)
        self.encrypt_output.pack(fill=tk.BOTH, expand=True)

        # Download buttons
        button_frame_out = ttk.Frame(output_frame)
        button_frame_out.pack(pady=5)

        self.download_encrypt_btn = ttk.Button(button_frame_out, text="Download Encrypted File",
                                               command=self.download_encrypt_result, state='disabled')
        self.download_encrypt_btn.pack(side=tk.LEFT, padx=5)

        self.copy_cipher_btn = ttk.Button(button_frame_out, text="Copy Ciphertext",
                                          command=self.copy_ciphertext, state='disabled')
        self.copy_cipher_btn.pack(side=tk.LEFT, padx=5)

        # Initialize
        self.toggle_encrypt_input()
        self.encrypt_input_var.trace('w', lambda *args: self.toggle_encrypt_input())

        return tab

    def create_decryption_tab(self):
        """Create the decryption tab"""
        tab = ttk.Frame(self.notebook)

        # Input section
        input_frame = ttk.LabelFrame(tab, text="Decryption Settings", padding="15")
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        # Input method
        ttk.Label(input_frame, text="Input Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.decrypt_input_var = tk.StringVar(value="file")
        ttk.Radiobutton(input_frame, text="Encrypted File", variable=self.decrypt_input_var,
                        value="file").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(input_frame, text="Ciphertext", variable=self.decrypt_input_var,
                        value="ciphertext").grid(row=0, column=2, sticky=tk.W)

        # File input for decryption
        self.file_decrypt_frame = ttk.Frame(input_frame)
        self.file_decrypt_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.file_decrypt_frame, text="Encrypted File:").pack(anchor=tk.W)
        file_select_frame = ttk.Frame(self.file_decrypt_frame)
        file_select_frame.pack(fill=tk.X, pady=5)
        self.decrypt_file_path = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.decrypt_file_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="Browse", command=self.browse_decrypt_file).pack(side=tk.LEFT)

        # Ciphertext input
        self.ciphertext_frame = ttk.Frame(input_frame)
        self.ciphertext_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.ciphertext_frame, text="Ciphertext (hex):").pack(anchor=tk.W)
        self.ciphertext_input = scrolledtext.ScrolledText(self.ciphertext_frame, height=4, width=80)
        self.ciphertext_input.pack(fill=tk.X, pady=5)

        # Decryption settings
        settings_frame = ttk.Frame(input_frame)
        settings_frame.grid(row=3, column=0, columnspan=3, sticky=tk.W + tk.E, pady=10)

        ttk.Label(settings_frame, text="DES Key (8 characters):").grid(row=0, column=0, sticky=tk.W)
        self.decrypt_key = ttk.Entry(settings_frame, width=20, font=('Arial', 10))
        self.decrypt_key.grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(settings_frame, text="Encryption Mode:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.decrypt_mode = ttk.Combobox(settings_frame, values=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
                                         state="readonly", width=15)
        self.decrypt_mode.set('CBC')
        self.decrypt_mode.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(settings_frame, text="IV/Nonce (hex):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.decrypt_iv = ttk.Entry(settings_frame, width=30, font=('Arial', 10))
        self.decrypt_iv.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Decrypt", command=self.process_decryption,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_decryption).pack(side=tk.LEFT, padx=5)

        # Output section
        output_frame = ttk.LabelFrame(tab, text="Decryption Results", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.decrypt_output = scrolledtext.ScrolledText(output_frame, height=10)
        self.decrypt_output.pack(fill=tk.BOTH, expand=True)

        # Download button
        self.download_decrypt_btn = ttk.Button(output_frame, text="Download Decrypted File",
                                               command=self.download_decrypt_result, state='disabled')
        self.download_decrypt_btn.pack(pady=5)

        # Initialize
        self.toggle_decrypt_input()
        self.decrypt_input_var.trace('w', lambda *args: self.toggle_decrypt_input())

        return tab

    def toggle_encrypt_input(self):
        """Toggle between text and file input for encryption"""
        if self.encrypt_input_var.get() == "text":
            self.text_frame.grid()
            self.file_frame.grid_remove()
        else:
            self.text_frame.grid_remove()
            self.file_frame.grid()

    def toggle_decrypt_input(self):
        """Toggle between file and ciphertext input for decryption"""
        if self.decrypt_input_var.get() == "file":
            self.file_decrypt_frame.grid()
            self.ciphertext_frame.grid_remove()
        else:
            self.file_decrypt_frame.grid_remove()
            self.ciphertext_frame.grid()

    def browse_encrypt_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            self.original_extension = os.path.splitext(filename)[1]

    def browse_decrypt_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.decrypt_file_path.set(filename)

    def des_encrypt(self, plaintext, key, mode='CBC'):
        """DES encryption function"""
        if len(key) != 8:
            raise ValueError("DES key must be 8 bytes long")

        iv_nonce = None

        if mode.upper() == 'ECB':
            cipher = DES.new(key, DES.MODE_ECB)
        elif mode.upper() == 'CBC':
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            iv_nonce = iv
        elif mode.upper() == 'CFB':
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_CFB, iv)
            iv_nonce = iv
        elif mode.upper() == 'OFB':
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_OFB, iv)
            iv_nonce = iv
        elif mode.upper() == 'CTR':
            nonce = get_random_bytes(4)
            counter = Counter.new(32, prefix=nonce)
            cipher = DES.new(key, DES.MODE_CTR, counter=counter)
            iv_nonce = nonce

        start_time = time.perf_counter()

        if mode.upper() in ['ECB', 'CBC']:
            padded_plaintext = pad(plaintext, DES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
        else:
            ciphertext = cipher.encrypt(plaintext)

        enc_time = time.perf_counter() - start_time

        return ciphertext, iv_nonce, enc_time

    def des_decrypt(self, ciphertext, key, iv_nonce, mode='CBC'):
        """DES decryption function"""
        if mode.upper() == 'ECB':
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted = cipher.decrypt(ciphertext)
            plaintext = unpad(decrypted, DES.block_size)
        elif mode.upper() == 'CBC':
            cipher = DES.new(key, DES.MODE_CBC, iv_nonce)
            decrypted = cipher.decrypt(ciphertext)
            plaintext = unpad(decrypted, DES.block_size)
        elif mode.upper() == 'CFB':
            cipher = DES.new(key, DES.MODE_CFB, iv_nonce)
            plaintext = cipher.decrypt(ciphertext)
        elif mode.upper() == 'OFB':
            cipher = DES.new(key, DES.MODE_OFB, iv_nonce)
            plaintext = cipher.decrypt(ciphertext)
        elif mode.upper() == 'CTR':
            counter = Counter.new(32, prefix=iv_nonce)
            cipher = DES.new(key, DES.MODE_CTR, counter=counter)
            plaintext = cipher.decrypt(ciphertext)

        return plaintext

    def process_encryption(self):
        """Handle encryption process"""
        try:
            self.status_var.set("Processing encryption...")

            if self.encrypt_input_var.get() == "text":
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

            key_str = self.encrypt_key.get().strip()
            if len(key_str) != 8:
                messagebox.showerror("Error", "DES key must be exactly 8 characters")
                return
            key = key_str.encode('utf-8')
            mode = self.encrypt_mode.get()

            ciphertext, iv_nonce, enc_time = self.des_encrypt(plaintext, key, mode)

            self.encrypt_output.delete(1.0, tk.END)
            self.encrypt_output.insert(tk.END, "ENCRYPTION SUCCESSFUL\n")
            self.encrypt_output.insert(tk.END, "=" * 50 + "\n\n")
            self.encrypt_output.insert(tk.END, f"Mode: {mode}\n")
            self.encrypt_output.insert(tk.END, f"Encryption Time: {enc_time * 1000:.3f} ms\n")
            self.encrypt_output.insert(tk.END, f"Original Size: {len(plaintext)} bytes\n")
            self.encrypt_output.insert(tk.END, f"Encrypted Size: {len(ciphertext)} bytes\n")

            if iv_nonce:
                self.encrypt_output.insert(tk.END, f"IV/Nonce: {iv_nonce.hex()}\n")

            # Only show ciphertext for text encryption, not for files
            if input_type == "text":
                self.encrypt_output.insert(tk.END, f"\nCiphertext (hex):\n")
                self.encrypt_output.insert(tk.END, f"{ciphertext.hex()}\n")
            else:
                self.encrypt_output.insert(tk.END,
                                           f"\nFile encrypted successfully. Use 'Download Encrypted File' to save the result.\n")

            self.last_encrypt_result = ciphertext
            self.last_encrypt_iv = iv_nonce
            self.last_input_type = input_type
            if input_type == "file":
                self.last_original_extension = self.original_extension

            self.download_encrypt_btn.config(state='normal')

            # Only enable copy ciphertext button for text encryption
            if input_type == "text":
                self.copy_cipher_btn.config(state='normal')
            else:
                self.copy_cipher_btn.config(state='disabled')

            self.status_var.set("Encryption completed successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.status_var.set("Encryption failed")

    def process_decryption(self):
        """Handle decryption process"""
        try:
            self.status_var.set("Processing decryption...")

            if self.decrypt_input_var.get() == "file":
                filepath = self.decrypt_file_path.get()
                if not filepath or not os.path.exists(filepath):
                    messagebox.showerror("Error", "Please select a valid encrypted file")
                    return

                with open(filepath, 'rb') as f:
                    file_data = f.read()

                mode = self.decrypt_mode.get()
                iv_hex = self.decrypt_iv.get().strip()

                if mode.upper() in ['CBC', 'CFB', 'OFB'] and len(file_data) >= 8:
                    iv_nonce = file_data[:8]
                    ciphertext = file_data[8:]
                elif mode.upper() == 'CTR' and len(file_data) >= 4:
                    iv_nonce = file_data[:4]
                    ciphertext = file_data[4:]
                else:
                    ciphertext = file_data
                    iv_nonce = bytes.fromhex(iv_hex) if iv_hex else None

            else:
                ciphertext_hex = self.ciphertext_input.get(1.0, tk.END).strip()
                if not ciphertext_hex:
                    messagebox.showerror("Error", "Please enter ciphertext in hex format")
                    return
                ciphertext = bytes.fromhex(ciphertext_hex)
                iv_hex = self.decrypt_iv.get().strip()
                iv_nonce = bytes.fromhex(iv_hex) if iv_hex else None
                mode = self.decrypt_mode.get()

            key_str = self.decrypt_key.get().strip()
            if len(key_str) != 8:
                messagebox.showerror("Error", "DES key must be exactly 8 characters")
                return
            key = key_str.encode('utf-8')

            start_time = time.perf_counter()
            plaintext = self.des_decrypt(ciphertext, key, iv_nonce, mode)
            dec_time = time.perf_counter() - start_time

            self.decrypt_output.delete(1.0, tk.END)
            self.decrypt_output.insert(tk.END, "DECRYPTION SUCCESSFUL\n")
            self.decrypt_output.insert(tk.END, "=" * 50 + "\n\n")
            self.decrypt_output.insert(tk.END, f"Mode: {mode}\n")
            self.decrypt_output.insert(tk.END, f"Decryption Time: {dec_time * 1000:.3f} ms\n")
            self.decrypt_output.insert(tk.END, f"Decrypted Size: {len(plaintext)} bytes\n\n")

            try:
                decoded = plaintext.decode('utf-8')
                self.decrypt_output.insert(tk.END, f"Decrypted Text:\n{decoded}\n")
            except:
                self.decrypt_output.insert(tk.END, "Decrypted data is binary (likely a file)\n")

            self.last_decrypt_result = plaintext
            self.download_decrypt_btn.config(state='normal')
            self.status_var.set("Decryption completed successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.status_var.set("Decryption failed")

    def download_encrypt_result(self):
        """Download encryption result"""
        if not hasattr(self, 'last_encrypt_result'):
            return

        file_types = [
            ("Encrypted files", "*.enc"),
            ("All files", "*.*")
        ]

        filename = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=file_types
        )

        if filename:
            try:
                with open(filename, 'wb') as f:
                    mode = self.encrypt_mode.get()
                    if mode.upper() in ['CBC', 'CFB', 'OFB']:
                        f.write(self.last_encrypt_iv + self.last_encrypt_result)
                    elif mode.upper() == 'CTR':
                        f.write(self.last_encrypt_iv + self.last_encrypt_result)
                    else:
                        f.write(self.last_encrypt_result)

                messagebox.showinfo("Success", f"Encrypted file saved as {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save encrypted file: {str(e)}")

    def download_decrypt_result(self):
        """Download decryption result"""
        if not hasattr(self, 'last_decrypt_result'):
            return

        file_types = [
            ("PDF files", "*.pdf"),
            ("Text files", "*.txt"),
            ("All files", "*.*")
        ]

        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=file_types
        )

        if filename:
            with open(filename, 'wb') as f:
                f.write(self.last_decrypt_result)

            # Try to open the file if it's a PDF
            if filename.lower().endswith('.pdf'):
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

    def copy_ciphertext(self):
        """Copy ciphertext to clipboard"""
        if hasattr(self, 'last_encrypt_result'):
            self.root.clipboard_clear()
            self.root.clipboard_append(self.last_encrypt_result.hex())
            self.root.update()
            messagebox.showinfo("Copied", "Ciphertext copied to clipboard")

    def clear_encryption(self):
        """Clear encryption inputs/outputs"""
        self.text_input.delete(1.0, tk.END)
        self.file_path.set("")
        self.encrypt_output.delete(1.0, tk.END)
        self.download_encrypt_btn.config(state='disabled')
        self.copy_cipher_btn.config(state='disabled')

    def clear_decryption(self):
        """Clear decryption inputs/outputs"""
        self.decrypt_file_path.set("")
        self.ciphertext_input.delete(1.0, tk.END)
        self.decrypt_output.delete(1.0, tk.END)
        self.download_decrypt_btn.config(state='disabled')


def main():
    root = tk.Tk()
    app = DESCryptoTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()