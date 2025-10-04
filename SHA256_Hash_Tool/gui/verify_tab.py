"""
SHA-256 Hash Verification tab
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
from crypto.hash_handler import HashHandler


class VerifyTab:
    def __init__(self, parent, colors):
        self.parent = parent
        self.colors = colors
        self.hash_handler = HashHandler()
        self.status_var = None
        self.create_interface()

    def set_status_var(self, status_var):
        """Set status variable for updating status bar"""
        self.status_var = status_var

    def create_interface(self):
        """Create the hash verification tab interface"""
        self.frame = ttk.Frame(self.parent)

        # Input section
        input_frame = ttk.LabelFrame(self.frame, text="Verification Input", padding="15")
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        # Data to verify
        ttk.Label(input_frame, text="Data to Verify:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.data_type_var = tk.StringVar(value="file")
        ttk.Radiobutton(input_frame, text="File", variable=self.data_type_var,
                        value="file").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(input_frame, text="Text", variable=self.data_type_var,
                        value="text").grid(row=0, column=2, sticky=tk.W)

        # File input
        self.file_frame = ttk.Frame(input_frame)
        self.file_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.file_frame, text="Select File:").pack(anchor=tk.W)
        file_select_frame = ttk.Frame(self.file_frame)
        file_select_frame.pack(fill=tk.X, pady=5)
        self.file_path = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT)

        # Text input
        self.text_frame = ttk.Frame(input_frame)
        self.text_frame.grid(row=2, column=0, columnspan=3, sticky=tk.W + tk.E, pady=5)
        ttk.Label(self.text_frame, text="Enter Text:").pack(anchor=tk.W)
        self.text_input = scrolledtext.ScrolledText(self.text_frame, height=3, width=80)
        self.text_input.pack(fill=tk.X, pady=5)

        # Expected hash input
        hash_frame = ttk.Frame(input_frame)
        hash_frame.grid(row=3, column=0, columnspan=3, sticky=tk.W + tk.E, pady=10)
        ttk.Label(hash_frame, text="Expected SHA-256 Hash:").pack(anchor=tk.W)
        self.expected_hash = scrolledtext.ScrolledText(hash_frame, height=2, width=80)
        self.expected_hash.pack(fill=tk.X, pady=5)

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Verify Hash", command=self.verify_hash,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Results section
        results_frame = ttk.LabelFrame(self.frame, text="Verification Result", padding="15")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.result_text = scrolledtext.ScrolledText(results_frame, height=8, width=80)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Initialize
        self.toggle_input()
        self.data_type_var.trace('w', lambda *args: self.toggle_input())

    def toggle_input(self):
        """Toggle between file and text input"""
        if self.data_type_var.get() == "file":
            self.file_frame.grid()
            self.text_frame.grid_remove()
        else:
            self.file_frame.grid_remove()
            self.text_frame.grid()

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def verify_hash(self):
        """Verify SHA-256 hash"""
        try:
            if self.status_var:
                self.status_var.set("Verifying SHA-256 hash...")

            # Get expected hash
            expected_hash_text = self.expected_hash.get(1.0, tk.END).strip()
            if not expected_hash_text:
                messagebox.showerror("Error", "Please enter the expected SHA-256 hash")
                return

            # Clean the hash (remove spaces, convert to lowercase)
            expected_hash_clean = expected_hash_text.replace(' ', '').replace('-', '').lower()

            if len(expected_hash_clean) != 64:
                messagebox.showerror("Error", "SHA-256 hash must be 64 characters long")
                return

            # Get data to verify
            if self.data_type_var.get() == "file":
                filepath = self.file_path.get()
                if not filepath or not os.path.exists(filepath):
                    messagebox.showerror("Error", "Please select a valid file")
                    return

                start_time = time.perf_counter()
                actual_hash = self.hash_handler.hash_file(filepath)
                end_time = time.perf_counter()

                data_type = "file"
                data_info = f"File: {os.path.basename(filepath)}"
                data_size = os.path.getsize(filepath)

            else:
                text = self.text_input.get(1.0, tk.END).strip()
                if not text:
                    messagebox.showerror("Error", "Please enter some text to verify")
                    return

                start_time = time.perf_counter()
                actual_hash = self.hash_handler.hash_text(text)
                end_time = time.perf_counter()

                data_type = "text"
                data_info = "Text input"
                data_size = len(text.encode('utf-8'))

            verification_time = end_time - start_time
            hashes_match = (actual_hash == expected_hash_clean)

            # Display results
            self.result_text.delete(1.0, tk.END)

            if hashes_match:
                self.result_text.insert(tk.END, "✅ VERIFICATION SUCCESSFUL\n", "success")
                self.result_text.insert(tk.END, "=" * 50 + "\n\n")
            else:
                self.result_text.insert(tk.END, "❌ VERIFICATION FAILED\n", "error")
                self.result_text.insert(tk.END, "=" * 50 + "\n\n")

            self.result_text.insert(tk.END, f"Data Type: {data_type}\n")
            self.result_text.insert(tk.END, f"{data_info}\n")
            self.result_text.insert(tk.END, f"Data Size: {data_size} bytes\n")
            self.result_text.insert(tk.END, f"Verification Time: {verification_time * 1000:.3f} ms\n\n")

            self.result_text.insert(tk.END, f"Expected Hash:\n{expected_hash_clean}\n\n")
            self.result_text.insert(tk.END, f"Actual Hash:\n{actual_hash}\n\n")

            if not hashes_match:
                self.result_text.insert(tk.END, "⚠️  WARNING: Hashes do not match!\n")
                self.result_text.insert(tk.END, "The data may have been modified or corrupted.\n")

            # Configure text tags for colors
            self.result_text.tag_configure("success", foreground="#059669")
            self.result_text.tag_configure("error", foreground="#DC2626")

            if self.status_var:
                if hashes_match:
                    self.status_var.set("Hash verification successful")
                else:
                    self.status_var.set("Hash verification failed - hashes don't match")

        except Exception as e:
            messagebox.showerror("Error", f"Hash verification failed: {str(e)}")
            if self.status_var:
                self.status_var.set("Hash verification failed")

    def clear(self):
        """Clear inputs/outputs"""
        self.file_path.set("")
        self.text_input.delete(1.0, tk.END)
        self.expected_hash.delete(1.0, tk.END)
        self.result_text.delete(1.0, tk.END)