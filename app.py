import webview
import tkinter as tk
from tkinter import filedialog
import base64
# from cryptography.fernet import Fernet # Replaced with AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os
import sys
import secrets
import string
import threading
import hashlib

# --- Helper Function for Resource Path ---
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
#--resrce path needd to be fix later-- 

# --- Global Variables ---
selected_file_path = None
selected_key_file_path = None

# --- Optimization: Lazy loading of cryptography modules ---
class CryptoComponents:
    def __init__(self):
        self._pbkdf2 = None
        self._aesgcm = None
        self._hashes = None

    @property
    def pbkdf2(self):
        if self._pbkdf2 is None:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            self._pbkdf2 = PBKDF2HMAC
        return self._pbkdf2

    @property
    def aesgcm(self):
        if self._aesgcm is None:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._aesgcm = AESGCM
        return self._aesgcm

    @property
    def hashes(self):
        if self._hashes is None:
            from cryptography.hazmat.primitives import hashes
            self._hashes = hashes
        return self._hashes

# Initialize crypto components
crypto = CryptoComponents()

# --- Cryptography Functions ---
def generate_key(password: str, salt: bytes, key_file_path: str = None) -> bytes:
    """Generates a key from a password, salt, and optionally a key file."""
    # Start with the password-based key derivation
    kdf = crypto.pbkdf2(
        algorithm=crypto.hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000, # NIST recommendation as of 2023
    )
    password_key = kdf.derive(password.encode())
    
    # If a key file is provided, incorporate it into the final key
    if key_file_path and os.path.exists(key_file_path):
        try:
            # We'll use the file's content as additional entropy
            # Read the file in chunks to handle large files
            file_hash = hashlib.sha256()
            with open(key_file_path, 'rb') as kf:
                while chunk := kf.read(8192):  # 8KB chunks
                    file_hash.update(chunk)
            
            file_key = file_hash.digest()
            
            # Combine password-derived key with file-derived key
            # Using XOR for combining keys
            final_key = bytes(a ^ b for a, b in zip(password_key, file_key))
            return final_key
        except Exception as e:
            print(f"Error processing key file: {e}")
            # If there's any error with the key file, fall back to password-only
            return password_key
    
    # If no key file is provided, just return the password-derived key
    return password_key

def encrypt_file(file_path: str, password: str, key_file_path: str = None):
    """Encrypts a file using AES-GCM with optional key file."""
    try:
        salt = os.urandom(16)
        key = generate_key(password, salt, key_file_path)
        aesgcm = crypto.aesgcm(key)
        nonce = os.urandom(12)  # GCM recommended nonce size is 12 bytes

        with open(file_path, 'rb') as file:
            original = file.read()

        encrypted = aesgcm.encrypt(nonce, original, None)  # No associated data

        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            # Store whether a key file was used (1 byte: 0=no, 1=yes)
            key_file_used = b'\x01' if key_file_path else b'\x00'
            # Store salt, nonce, then ciphertext
            encrypted_file.write(key_file_used + salt + nonce + encrypted)
        
        return True, f"File encrypted successfully: {os.path.basename(encrypted_file_path)}"
    except Exception as e:
        print(f"Error encrypting: {e}")
        return False, f"Error during encryption: {e}"

def decrypt_file(file_path: str, password: str, key_file_path: str = None):
    """Decrypts a file using AES-GCM with optional key file."""
    try:
        with open(file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()

        # Extract key file flag (1 byte)
        key_file_required = data[0] == 1
        
        # Extract salt (16 bytes) and nonce (12 bytes)
        salt = data[1:17]  # Adjusted for the key file flag
        nonce = data[17:29]  # Adjusted for the key file flag
        encrypted_data = data[29:]  # Adjusted for the key file flag

        # If the file was encrypted with a key file but none is provided, return error
        if key_file_required and not key_file_path:
            return False, "This file was encrypted with a key file. Please select the key file."

        key = generate_key(password, salt, key_file_path)
        aesgcm = crypto.aesgcm(key)

        decrypted = aesgcm.decrypt(nonce, encrypted_data, None)  # No associated data

        decrypted_file_path = file_path.replace('.enc', '')
        # Avoid overwriting existing files without confirmation
        if os.path.exists(decrypted_file_path):
             base, ext = os.path.splitext(decrypted_file_path)
             decrypted_file_path = f"{base}_decrypted{ext}"

        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        return True, f"File decrypted successfully: {os.path.basename(decrypted_file_path)}"
    except InvalidTag:
        # Specific exception for authentication failure
        if key_file_path:
            return False, "Decryption failed: Incorrect password, wrong key file, or corrupted file."
        else:
            return False, "Decryption failed: Incorrect password or corrupted file."
    except Exception as e:
        print(f"Error decrypting: {e}")
        return False, f"Error during decryption: {str(e)}"

def verify_file_integrity(file_path: str, password: str, key_file_path: str = None):
    """Verifies only the integrity of an encrypted file without fully decrypting it."""
    try:
        with open(file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()

        # Check if file has minimum required size for key flag + salt + nonce + tag
        if len(data) < 1 + 16 + 12 + 16:  # flag(1) + salt(16) + nonce(12) + minimum tag size(16)
            return False, "File is too small to be a valid encrypted file."

        # Extract key file flag (1 byte)
        key_file_required = data[0] == 1
        
        # If the file was encrypted with a key file but none is provided, return error
        if key_file_required and not key_file_path:
            return False, "This file was encrypted with a key file. Please select the key file."

        # Extract salt (16 bytes) and nonce (12 bytes)
        salt = data[1:17]  # Adjusted for the key file flag
        nonce = data[17:29]  # Adjusted for the key file flag
        encrypted_data = data[29:]  # Adjusted for the key file flag

        key = generate_key(password, salt, key_file_path)
        aesgcm = crypto.aesgcm(key)

        # In GCM, we need to perform decryption to verify the tag,
        # but we'll only verify a small portion (first 32 bytes or entire file if small)
        verification_size = min(32, len(encrypted_data))
        verification_chunk = encrypted_data[:verification_size]
        
        try:
            # Attempt to decrypt just the verification chunk to check authenticity
            # This will raise InvalidTag if authentication fails
            aesgcm.decrypt(nonce, verification_chunk, None)
            return True, "File integrity verified successfully. The password and key file (if required) are correct."
        except InvalidTag:
            if key_file_path:
                return False, "Integrity verification failed: Incorrect password, wrong key file, or corrupted file."
            else:
                return False, "Integrity verification failed: Incorrect password or corrupted file."
            
    except Exception as e:
        print(f"Error verifying integrity: {e}")
        return False, f"Error during integrity verification: {str(e)}"

# --- Password Generation --- 
def generate_password(length=16, use_special_chars=True):
     """Generates a secure random password."""
     alphabet = string.ascii_letters + string.digits
     if use_special_chars:
         alphabet += string.punctuation
     password = ''.join(secrets.choice(alphabet) for i in range(length))
     return password

# --- Background initialization ---
def preload_modules():
    """Preload modules in background to speed up first use"""
    try:
        # Force initialization of crypto components
        _ = crypto.hashes.SHA256()
        _ = crypto.pbkdf2(
            algorithm=crypto.hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=1,
        )
        _ = crypto.aesgcm(os.urandom(32))
    except Exception as e:
        print(f"Preloading error (non-critical): {e}")

# Start preloading in background
threading.Thread(target=preload_modules, daemon=True).start()

# --- pywebview API --- 
class Api:
    def select_file(self):
        global selected_file_path
        root = tk.Tk()
        root.withdraw() # Hide the main tkinter window
        root.wm_attributes('-topmost', 1) # Bring the dialog to the front
        file_path = filedialog.askopenfilename(parent=root)
        root.destroy()
        if file_path:
            selected_file_path = file_path
            return {"success": True, "filePath": file_path, "fileName": os.path.basename(file_path)}
        else:
            selected_file_path = None
            return {"success": False}
    
    def select_key_file(self):
        """Select a file to use as a key file"""
        global selected_key_file_path
        root = tk.Tk()
        root.withdraw() # Hide the main tkinter window
        root.wm_attributes('-topmost', 1) # Bring the dialog to the front
        file_path = filedialog.askopenfilename(
            parent=root,
            title="Select Key File",
            filetypes=[("All files", "*.*")]
        )
        root.destroy()
        if file_path:
            selected_key_file_path = file_path
            return {"success": True, "filePath": file_path, "fileName": os.path.basename(file_path)}
        else:
            selected_key_file_path = None
            return {"success": False}
    
    def clear_key_file(self):
        """Clear the selected key file"""
        global selected_key_file_path
        selected_key_file_path = None
        return {"success": True}

    def encrypt(self, password, use_key_file=False):
        if not selected_file_path:
            return {"success": False, "message": "No file selected."}
        if not password:
            return {"success": False, "message": "Please enter a password."}
        
        key_file = selected_key_file_path if use_key_file else None
        if use_key_file and not key_file:
            return {"success": False, "message": "Key file option selected but no key file chosen."}

        success, message = encrypt_file(selected_file_path, password, key_file)
        return {"success": success, "message": message}

    def decrypt(self, password, use_key_file=False):
        if not selected_file_path:
            return {"success": False, "message": "No file selected."}
        if not password:
            return {"success": False, "message": "Please enter a password."}
        if not selected_file_path.endswith('.enc'):
            return {"success": False, "message": "The selected file is not an encrypted file (.enc)."}
        
        key_file = selected_key_file_path if use_key_file else None

        success, message = decrypt_file(selected_file_path, password, key_file)
        return {"success": success, "message": message}

    def generate_password_api(self, length=16, use_special_chars=True):
        """API endpoint to generate a password, accepting length and special char options."""
        try:
            # Validate length server-side as well (basic check) ( need to add a check for this)
            if not isinstance(length, int) or not (8 <= length <= 128):
                print(f"Invalid length received: {length}, defaulting to 16.") # Added logging
                length = 16 # Default to 16 if invalid
            if not isinstance(use_special_chars, bool):
                print(f"Invalid use_special_chars received: {use_special_chars}, defaulting to True.") # Added logging
                use_special_chars = True

            password = generate_password(length=length, use_special_chars=use_special_chars)
            return {"success": True, "password": password}
        except Exception as e:
            print(f"Error generating password: {e}")
            return {"success": False, "message": "Error generating password."}

    def verify_integrity(self, password, use_key_file=False):
        """API method to verify file integrity without full decryption."""
        if not selected_file_path:
            return {"success": False, "message": "No file selected."}
        if not password:
            return {"success": False, "message": "Please enter a password."}
        if not selected_file_path.endswith('.enc'):
            return {"success": False, "message": "The selected file is not an encrypted file (.enc)."}
        
        key_file = selected_key_file_path if use_key_file else None

        success, message = verify_file_integrity(selected_file_path, password, key_file)
        return {"success": success, "message": message}

# --- Main Application Setup ---
if __name__ == '__main__':
    # Create API instance
    api = Api()
    
    # Configure webview window options for faster loading
    window_options = {
        'width': 650, 
        'height': 700,
        'background_color': '#1a1d24',  # Match background color to avoid flashing
        'text_select': False,  # Disable text selection for better performance
        'frameless': False,
        'easy_drag': False,
    }
    
    # Use resource_path for cross-platform and PyInstaller compatibility
    html_file = resource_path('index.html')
    
    # Create the webview window
    window = webview.create_window('Encrypty-chan', html_file, js_api=api, **window_options)
    
    # Start the webview
    webview.start(debug=False)