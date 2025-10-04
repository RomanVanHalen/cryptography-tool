# aes_implementation.py
import time
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter


def aes_encrypt(plaintext, key, mode='CBC', key_size=128, **kwargs):
    """Encrypt using AES in selected mode"""
    # Validate key size
    if key_size == 128:
        if len(key) != 16:
            raise ValueError("AES-128 key must be 16 bytes long")
    elif key_size == 256:
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes long")
    else:
        raise ValueError("Key size must be 128 or 256")

    iv_nonce = None
    tag = None

    start_time = time.perf_counter()

    if mode.upper() == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)

    elif mode.upper() == 'CBC':
        iv = kwargs.get('iv', get_random_bytes(16))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        iv_nonce = iv

    elif mode.upper() == 'CFB':
        iv = kwargs.get('iv', get_random_bytes(16))
        cipher = AES.new(key, AES.MODE_CFB, iv)
        iv_nonce = iv

    elif mode.upper() == 'OFB':
        iv = kwargs.get('iv', get_random_bytes(16))
        cipher = AES.new(key, AES.MODE_OFB, iv)
        iv_nonce = iv

    elif mode.upper() == 'CTR':
        nonce = kwargs.get('nonce', get_random_bytes(8))
        counter = Counter.new(64, prefix=nonce)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        iv_nonce = nonce

    elif mode.upper() == 'GCM':
        iv = kwargs.get('iv', get_random_bytes(12))  # 12-byte IV for GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        iv_nonce = iv
        enc_time = time.perf_counter() - start_time
        return ciphertext, iv_nonce, enc_time, tag

    else:
        raise ValueError("Unsupported mode")

    # Pad for modes that need it
    if mode.upper() in ['ECB', 'CBC']:
        padded_plaintext = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
    else:
        # Stream modes don't need padding
        ciphertext = cipher.encrypt(plaintext)

    enc_time = time.perf_counter() - start_time

    return ciphertext, iv_nonce, enc_time


def aes_decrypt(ciphertext, key, iv_nonce, mode='CBC', tag=None, **kwargs):
    """Decrypt using AES in selected mode"""
    start_time = time.perf_counter()

    if mode.upper() == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted, AES.block_size)

    elif mode.upper() == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv_nonce)
        decrypted = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted, AES.block_size)

    elif mode.upper() == 'CFB':
        cipher = AES.new(key, AES.MODE_CFB, iv_nonce)
        plaintext = cipher.decrypt(ciphertext)

    elif mode.upper() == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB, iv_nonce)
        plaintext = cipher.decrypt(ciphertext)

    elif mode.upper() == 'CTR':
        counter = Counter.new(64, prefix=iv_nonce)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        plaintext = cipher.decrypt(ciphertext)

    elif mode.upper() == 'GCM':
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv_nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    else:
        raise ValueError("Unsupported mode")

    dec_time = time.perf_counter() - start_time

    return plaintext


def find_file(filename):
    """Smart file finder that handles missing extensions"""
    filename = filename.strip('"\'')

    if os.path.exists(filename):
        return filename

    if '.' not in filename:
        for ext in ['.pdf', '.txt', '.docx', '.jpg', '.png', '.bin']:
            candidate = filename + ext
            if os.path.exists(candidate):
                print(f"Found: {candidate}")
                return candidate

    return None


def read_file(filename):
    """Read content from file with better error handling"""
    try:
        actual_filename = find_file(filename)

        if actual_filename is None:
            print(f"File not found: {filename}")
            print(f"Current directory: {os.getcwd()}")
            print("Available files:")
            for file in os.listdir('.'):
                if os.path.isfile(file):
                    print(f"  {file}")
            return None

        with open(actual_filename, 'rb') as f:
            content = f.read()
            print(f"Successfully read {len(content)} bytes from {actual_filename}")
            return content

    except Exception as e:
        print(f"Error reading file: {e}")
        return None


def format_time(seconds):
    """Format time to show appropriate units"""
    if seconds < 0.000001:
        return f"{seconds * 1000000:.3f} μs"
    elif seconds < 0.001:
        return f"{seconds * 1000:.3f} ms"
    else:
        return f"{seconds:.6f} s"


def main():
    print("AES Encryption Mode Analysis")
    print("=" * 50)

    # Choose AES version
    print("\nChoose AES version:")
    print("1. AES-128 (16-character key)")
    print("2. AES-256 (32-character key)")
    choice = input("Enter choice (1 or 2): ")

    if choice == "1":
        key_size = 128
        key_input = input("Enter 16-character key for AES-128: ")
        if len(key_input) != 16:
            print("Using default key '16bytekey12345678'")
            key = b"16bytekey12345678"
        else:
            key = key_input.encode('utf-8')
    else:
        key_size = 256
        key_input = input("Enter 32-character key for AES-256: ")
        if len(key_input) != 32:
            print("Using default 32-byte key")
            key = b"32bytekey123456789012345678901234"
        else:
            key = key_input.encode('utf-8')

    # Input choice
    print("\nChoose input method:")
    print("1. Keyboard input")
    print("2. File input")
    input_choice = input("Enter choice (1 or 2): ")

    plaintext = None
    input_source = ""

    if input_choice == "1":
        # Keyboard input
        text = input("Enter the text to encrypt: ")
        plaintext = text.encode('utf-8')
        input_source = "keyboard input"
    else:
        # File input
        print("\nAvailable files in current directory:")
        for file in os.listdir('.'):
            if os.path.isfile(file):
                print(f"  {file}")

        filename = input("\nEnter filename to encrypt: ")
        plaintext = read_file(filename)
        if plaintext is None:
            return
        input_source = f"file: {filename}"

    # Test all modes
    modes = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM']

    print(f"\nAES-{key_size} Analysis")
    print(f"Input source: {input_source}")
    print(f"Key: {key.decode('utf-8')}")
    print(f"Data size: {len(plaintext)} bytes")

    print(f"\n{'Mode':<6} {'Enc Time':<12} {'Ciphertext Size':<15} {'IV/Nonce':<12} {'Status':<8}")
    print("-" * 70)

    results = []

    for mode in modes:
        try:
            if mode == 'GCM':
                # GCM returns tag separately
                ciphertext, iv_nonce, enc_time, tag = aes_encrypt(plaintext, key, mode, key_size)
                decrypted_text = aes_decrypt(ciphertext, key, iv_nonce, mode, tag)
            else:
                ciphertext, iv_nonce, enc_time = aes_encrypt(plaintext, key, mode, key_size)
                decrypted_text = aes_decrypt(ciphertext, key, iv_nonce, mode)

            # Verify
            status = "PASS" if plaintext == decrypted_text else "FAIL"

            iv_display = iv_nonce.hex()[:8] + "..." if iv_nonce and len(iv_nonce.hex()) > 8 else (
                iv_nonce.hex() if iv_nonce else "None")

            print(f"{mode:<6} {format_time(enc_time):<12} {len(ciphertext):<15} {iv_display:<12} {status:<8}")

            results.append({
                'mode': mode,
                'key_size': key_size,
                'enc_time': enc_time,
                'ciphertext': ciphertext,
                'decrypted': decrypted_text,
                'iv_nonce': iv_nonce,
                'status': status
            })

        except Exception as e:
            print(f"{mode:<6} {'Error':<12} {'N/A':<15} {'N/A':<12} {'FAIL':<8}")

    # Show decryption verification
    print(f"\n" + "=" * 50)
    print("DECRYPTION VERIFICATION")
    print("=" * 50)

    for result in results:
        if result['status'] == 'PASS':
            print(f"{result['mode']}: ✓ Successfully decrypted")
        else:
            print(f"{result['mode']}: ✗ Decryption failed")


if __name__ == "__main__":
    main()