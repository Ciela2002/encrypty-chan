# File Encryptor

A simple tool to encrypt and decrypt files using a password.

## Features

*   Easy file selection via a graphical interface.
*   File encryption using the AES algorithm.
*   Secure key derivation from a password using PBKDF2HMAC.
*   Secure password generation.
*   Simple web-based user interface (via pywebview).

## Installation

1.  **Prerequisites:** Ensure Python 3 is installed on your system.
2.  **Clone the repository (if applicable) or download the files.**
3.  **Install dependencies:**
    Open a terminal or command prompt in the project folder and run:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  Run the application:
    ```bash
    python app.py
    ```
2.  The user interface will open in a window.
3.  **Select a file:** Click the "Select File" button to choose the file you want to encrypt or decrypt.
4.  **Encrypt:**
    *   Enter a secure password in the "Password" field.
    *   Click the "Encrypt" button.
    *   A new file with the `.enc` extension will be created in the same folder as the original file.
5.  **Decrypt:**
    *   Select an encrypted file (with the `.enc` extension).
    *   Enter the correct password used for encryption.
    *   Click the "Decrypt" button.
    *   The decrypted file will be saved (with `_decrypted` added to the name if a file with the same name already exists).
6.  **Generate Password:** Click "Generate Password" to get a random and secure password.

## Technologies Used

*   **Python:** Main language.
*   **pywebview:** To create a lightweight web user interface.
*   **Tkinter:** Used for the file selection dialog box.
*   **cryptography:** Library for AES encryption operations and key derivation.
*   **HTML/CSS/JavaScript:** For the user interface.