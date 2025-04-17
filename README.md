# Encrypty-chan

A secure and easy-to-use file encryption tool with an intuitive interface.

## Features

* Easy file selection via a graphical interface
* Robust file encryption using AES-256 in GCM mode
* Secure key derivation from passwords using PBKDF2
* Random secure password generator
* Clean and intuitive user interface

## Installation

### Using the Executable (Recommended)

1. Download the latest executable from the releases section

2. No additional installation required - the application is ready to use!

### System Requirements

* Windows 10/11, macOS 10.14+, or Linux (with GTK 3+)
* 50 MB of free disk space
* No internet connection required

## Usage

1. Launch the application by double-clicking the executable.

2. **Select a file:** Click the "Select File" button to choose the file you want to encrypt or decrypt.

3. **Encrypt:**
   * Enter a secure password in the "Password" field.
   * Click the "Encrypt" button.
   * A new file with the `.enc` extension will be created in the same folder as the original file.

4. **Decrypt:**
   * Select an encrypted file (with the `.enc` extension).
   * Enter the correct password used for encryption.
   * Click the "Decrypt" button.
   * The decrypted file will be saved (with `_decrypted` added to the name if a file with the same name already exists).

5. **Generate Password:** Click "Generate Password" to get a random and secure password.

## Security

This application implements modern cryptographic standards:
* AES-256 in Galois/Counter Mode (GCM) for encryption and authentication
* PBKDF2 with many iterations for secure key derivation
* Cryptographically secure random number generation

For more details on the cryptographic implementation, please refer to the ENCRYPTION_DETAILS.md file included with the release.

## Troubleshooting

If you encounter any issues:
1. Ensure you're using the correct password for decryption
2. Verify that you have write permissions in the folder where files are being saved
3. Check that the file isn't in use by another application

## License

This software is distributed under the MIT License.