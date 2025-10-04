"""
SHA-256 Hash Generation tab
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
from crypto.hash_handler import HashHandler


class HashTab:
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
        """Create the hash generation tab interface"""
        self.frame = ttk.Frame(self.parent)

        # Input section
        input_frame = ttk.LabelFrame(self.frame, text="Input Data", padding="15")
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

        # Action buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Generate SHA-256 Hash", command=self.generate_hash,
                   style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)

        # Output section
        output_frame = ttk.LabelFrame(self.frame, text="SHA-256 Hash Result", padding="15")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Hash result
        ttk.Label(output_frame, text="SHA-256 Hash:").pack(anchor=tk.W)
        self.hash_output = scrolledtext.ScrolledText(output_frame, height=3, width=80)
        self.hash_output.pack(fill=tk.X, pady=5)

        # Hash actions
        hash_actions_frame = ttk.Frame(output_frame)
        hash_actions_frame.pack(fill=tk.X, pady=5)

        self.copy_hash_btn = ttk.Button(hash_actions_frame, text="Copy Hash",
                                        command=self.copy_hash, state='disabled')
        self.copy_hash_btn.pack(side=tk.LEFT, padx=5)

        self.save_hash_btn = ttk.Button(hash_actions_frame, text="Save Hash to File",
                                        command=self.save_hash, state='disabled')
        self.save_hash_btn.pack(side=tk.LEFT, padx=5)

        # Additional info
        info_frame = ttk.LabelFrame(output_frame, text="Hash Information", padding="10")
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

    def generate_hash(self):
        """Generate SHA-256 hash"""
        try:
            if self.status_var:
                self.status_var.set("Generating SHA-256 hash...")

            if self.input_var.get() == "text":
                text = self.text_input.get(1.0, tk.END).strip()
                if not text:
                    messagebox.showerror("Error", "Please enter some text to hash")
                    return

                start_time = time.perf_counter()
                hash_result = self.hash_handler.hash_text(text)
                end_time = time.perf_counter()

                input_type = "text"
                input_size = len(text.encode('utf-8'))

            else:
                filepath = self.file_path.get()
                if not filepath or not os.path.exists(filepath):
                    messagebox.showerror("Error", "Please select a valid file")
                    return

                start_time = time.perf_counter()
                hash_result = self.hash_handler.hash_file(filepath)
                end_time = time.perf_counter()

                input_type = "file"
                input_size = os.path.getsize(filepath)
                filename = os.path.basename(filepath)

            hash_time = end_time - start_time

            # Display results
            self.hash_output.delete(1.0, tk.END)
            self.hash_output.insert(tk.END, hash_result)

            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, f"Input Type: {input_type.capitalize()}\n")
            self.info_text.insert(tk.END, f"Input Size: {input_size} bytes\n")
            self.info_text.insert(tk.END, f"Hash Time: {hash_time * 1000:.3f} ms\n")
            self.info_text.insert(tk.END, f"Hash Length: {len(hash_result)} characters\n")

            if input_type == "file":
                self.info_text.insert(tk.END, f"File: {filename}\n")

            self.last_hash = hash_result
            self.copy_hash_btn.config(state='normal')
            self.save_hash_btn.config(state='normal')

            if self.status_var:
                self.status_var.set("SHA-256 hash generated successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Hash generation failed: {str(e)}")
            if self.status_var:
                self.status_var.set("Hash generation failed")

    def copy_hash(self):
        """Copy hash to clipboard"""
        if hasattr(self, 'last_hash'):
            self.frame.clipboard_clear()
            self.frame.clipboard_append(self.last_hash)
            self.frame.update()
            messagebox.showinfo("Copied", "SHA-256 hash copied to clipboard")

    def save_hash(self):
        """Save hash to file"""
        if not hasattr(self, 'last_hash'):
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    if self.input_var.get() == "file":
                        filepath = self.file_path.get()
                        filename_only = os.path.basename(filepath)
                        f.write(f"File: {filename_only}\n")
                    f.write(f"SHA-256 Hash: {self.last_hash}\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

                messagebox.showinfo("Success", f"Hash saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save hash: {str(e)}")

    def clear(self):
        """Clear inputs/outputs"""
        self.text_input.delete(1.0, tk.END)
        self.file_path.set("")
        self.hash_output.delete(1.0, tk.END)
        self.info_text.delete(1.0, tk.END)
        self.copy_hash_btn.config(state='disabled')
        self.save_hash_btn.config(state='disabled')