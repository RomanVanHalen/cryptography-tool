"""
File handling utilities for Hash Tool
"""

import os
import subprocess
import sys


class FileHandler:
    @staticmethod
    def try_open_file(filename):
        """Try to open a file with the default application"""
        try:
            if os.name == 'nt':  # Windows
                os.startfile(filename)
            elif sys.platform == "darwin":  # macOS
                subprocess.Popen(["open", filename])
            else:  # Linux
                subprocess.Popen(["xdg-open", filename])
            return True
        except Exception as e:
            return False

    @staticmethod
    def get_file_info(filepath):
        """Get file information for display"""
        if not os.path.exists(filepath):
            return None

        stat = os.stat(filepath)
        return {
            'filename': os.path.basename(filepath),
            'size': stat.st_size,
            'modified': stat.st_mtime,
            'created': stat.st_ctime
        }

    @staticmethod
    def format_file_size(size_bytes):
        """Format file size in human-readable format"""
        if size_bytes == 0:
            return "0 B"

        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1

        return f"{size_bytes:.2f} {size_names[i]}"