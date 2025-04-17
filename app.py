import webview
import tkinter as tk
from tkinter import filedialog
import base64
# from cryptography.fernet import Fernet # Replaced with AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import sys
import secrets
import string
import threading

# --- Helper Function for Resource Path ---
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# --- Global Variables ---
selected_file_path = None

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
def generate_key(password: str, salt: bytes) -> bytes:
    """Generates a key from a password and salt."""
    kdf = crypto.pbkdf2(
        algorithm=crypto.hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000, # NIST recommendation as of 2023
    )
    key = kdf.derive(password.encode()) # Removed base64 encoding
    return key

def encrypt_file(file_path: str, password: str):
    """Encrypts a file using AES-GCM."""
    try:
        salt = os.urandom(16)
        key = generate_key(password, salt) # Key is derived via PBKDF2HMAC
        aesgcm = crypto.aesgcm(key)
        nonce = os.urandom(12) # GCM recommended nonce size is 12 bytes

        with open(file_path, 'rb') as file:
            original = file.read()

        encrypted = aesgcm.encrypt(nonce, original, None) # No associated data

        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            # Store salt, nonce, then ciphertext
            encrypted_file.write(salt + nonce + encrypted)
        return True, f"File encrypted successfully: {os.path.basename(encrypted_file_path)}"
    except Exception as e:
        print(f"Error encrypting: {e}")
        return False, f"Error during encryption: {e}"

def decrypt_file(file_path: str, password: str):
    """Decrypts a file using AES-GCM."""
    try:
        with open(file_path, 'rb') as encrypted_file:
            data = encrypted_file.read()

        # Extract salt (16 bytes) and nonce (12 bytes)
        salt = data[:16]
        nonce = data[16:28] # 16 + 12 = 28
        encrypted_data = data[28:]

        key = generate_key(password, salt)
        aesgcm = crypto.aesgcm(key)

        decrypted = aesgcm.decrypt(nonce, encrypted_data, None) # No associated data

        decrypted_file_path = file_path.replace('.enc', '')
        # Avoid overwriting existing files without confirmation (simple approach)
        if os.path.exists(decrypted_file_path):
             base, ext = os.path.splitext(decrypted_file_path)
             decrypted_file_path = f"{base}_decrypted{ext}"

        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        return True, f"File decrypted successfully: {os.path.basename(decrypted_file_path)}"
    except Exception as e: # Includes InvalidTag for GCM authentication failure
        print(f"Error decrypting: {e}")
        return False, f"Error during decryption: Incorrect password or corrupted file."

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

    def encrypt(self, password):
        if not selected_file_path:
            return {"success": False, "message": "No file selected."}
        if not password:
             return {"success": False, "message": "Please enter a password."}

        success, message = encrypt_file(selected_file_path, password)
        return {"success": success, "message": message}

    def decrypt(self, password):
        if not selected_file_path:
            return {"success": False, "message": "No file selected."}
        if not password:
             return {"success": False, "message": "Please enter a password."}
        if not selected_file_path.endswith('.enc'):
            return {"success": False, "message": "The selected file is not an encrypted file (.enc)."}

        success, message = decrypt_file(selected_file_path, password)
        return {"success": success, "message": message}

    def generate_password_api(self, length=16, use_special_chars=True):
        """API endpoint to generate a password, accepting length and special char options."""
        try:
            # Validate length server-side as well (basic check)
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