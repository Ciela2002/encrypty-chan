# Encrypty-chan

<p align="center">
  <img src="favi.png" alt="Encrypty-chan Logo" width="150" height="150"/>
</p>

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

6. **Key File (Optional):**
   * Enable the "Use key file for additional security" option.
   * Select any file to use as an additional security key.
   * You will need the same key file when decrypting the file.

7. **Verify Integrity:**
   * Select an encrypted file and enter the password.
   * Click "Verify Integrity" to check if the file is valid without decrypting it.

## Security

This application implements modern cryptographic standards:
* AES-256 in Galois/Counter Mode (GCM) for encryption and authentication
* PBKDF2 with many iterations for secure key derivation
* Cryptographically secure random number generation
* Optional key file support for two-factor security (something you know + something you have)

For more details on the cryptographic implementation, please refer to the ENCRYPTION_DETAILS.md file included with the release.

## Troubleshooting

If you encounter any issues:
1. Ensure you're using the correct password for decryption
2. Verify that you have write permissions in the folder where files are being saved
3. Check that the file isn't in use by another application
4. If using a key file, make sure it's the exact same file used during encryption

## Changelog

### Version 1.1.0 (17/04/2025)

* **New Feature:** Added file integrity verification - Allows checking if a file can be decrypted without actually decrypting it
* **New Feature:** Added key file support - Use any file as an additional security factor for encryption/decryption
* **Enhancement:** Improved error messages for decryption failures
* **Documentation:** Updated security information with details about new features

### Version 1.0.0 (Initial Release)

* Basic file encryption and decryption functionality
* Password generation capabilities
* AES-256-GCM encryption with PBKDF2 key derivation

## License

This software is distributed under the MIT License.