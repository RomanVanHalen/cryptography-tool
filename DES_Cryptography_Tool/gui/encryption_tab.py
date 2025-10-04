"""
Encryption tab implementation
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from crypto.des_handler import DESHandler


class EncryptionTab:
    def __init__(self, parent, colors):
        self.parent = parent
        self.colors = colors
        self.des_handler = DESHandler()
        self.create_interface()

    def create_interface(self):
        """Create the encryption tab interface"""
        self.frame = ttk.Frame(self.parent)

        # Input section
        input_frame = ttk.LabelFrame(self.frame, text="Encryption Settings", padding="15")
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

        # Encryption settings
        settings_frame = ttk.Frame(input_frame)
        settings_frame.grid(row=3, column=0, columnspan=3, sticky=tk.W + tk.E, pady=10)

        ttk.Label(settings_frame, text="DES Key (8 characters):").grid(row=0, column=0, sticky=tk.W)
        self.key_entry = ttk.Entry(settings_frame, width=20, font=('Arial', 10))
        self.key_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.key_entry.insert(0, "8bytekey")

        ttk.Label(settings_frame, text="Encryption Mode:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.mode_combo = ttk.Combobox(settings_frame, values=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
                                       state="readonly", width=15)
        self.mode_combo.set('CBC')
        self.mode_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Encrypt", command=self.process_encryption,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Output section
        output_frame = ttk.LabelFrame(self.frame, text="Encryption Results", padding="15")
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
            self.original_extension = os.path.splitext(filename)[1]

    def process_encryption(self):
        """Handle encryption process"""
        try:
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
            if len(key_str) != 8:
                messagebox.showerror("Error", "DES key must be exactly 8 characters")
                return

            mode = self.mode_combo.get()
            result = self.des_handler.encrypt(plaintext, key_str.encode('utf-8'), mode)

            self.display_results(result, input_type)
            self.last_result = result
            self.last_input_type = input_type

            if input_type == "file":
                self.last_original_extension = self.original_extension

            self.download_btn.config(state='normal')
            self.copy_btn.config(state='normal' if input_type == "text" else 'disabled')

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def display_results(self, result, input_type):
        """Display encryption results"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "ENCRYPTION SUCCESSFUL\n")
        self.output_text.insert(tk.END, "=" * 50 + "\n\n")
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
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )

        if filename:
            try:
                self.des_handler.save_encrypted_file(
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