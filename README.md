# AES-256 Encryption/Decryption Tool

This tool provides a graphical user interface (GUI) for encrypting and decrypting messages using the AES-256 encryption algorithm. It also allows users to save encrypted messages to a database, view saved messages, delete messages, and export/import encrypted messages to/from files.

## Features:

- Encryption: Users can enter a string of text to encrypt using AES-256 encryption. Upon encryption, the tool generates a random encryption key, encrypts the message, and stores both the encrypted message and the encryption key in a SQLite database.

- Decryption: Users can decrypt a message by entering the message ID associated with the encrypted message in the database. The tool retrieves the encrypted message and its encryption key, decrypts the message using AES-256 decryption, and displays the decrypted message.

- View Saved Messages: Users can view all saved encrypted messages stored in the database. Each message is displayed along with its unique ID, encrypted message, and encryption key.

- Delete Message: Users can delete a specific encrypted message from the database by providing its ID.

- Export/Import Messages: Users can export encrypted messages to a text file and import encrypted messages from a text file. This feature allows users to backup and restore encrypted messages.

## Installation:

Python: Make sure you have Python 3.x installed on your system. You can download it from the official Python website.

Dependencies: Install the required dependencies using pip, Python's package manager. Open your terminal/command prompt and run the following command:

`pip install tkinter cryptography`
This command will install Tkinter for GUI support and the cryptography library for encryption and decryption.

Clone Repository: Clone this repository to your local machine:

`git clone https://github.com/your-username/aes-256-encryption-tool.git`
//out intructions here


## Example Usage:

1. Encryption:
   Enter the text you want to encrypt in the provided input field.
   Click the "Encrypt and Save" button.
   The tool will generate a random encryption key, encrypt the text using AES-256, and save the encrypted message along with the encryption key in the database.

2. Decryption:
   Enter the ID of the encrypted message you want to decrypt in the input field.
   Click the "Decrypt" button.
   The tool will retrieve the encrypted message and its encryption key from the database, decrypt the message using AES-256, and display the decrypted text.

3. View Saved Messages:
   Click the "View Saved Encrypted Messages" button to display all saved encrypted messages along with their IDs, encrypted messages, and encryption keys.

4. Delete Message:
   Enter the ID of the message you want to delete in the input field.
   Click the "Delete Encrypted Message" button.
   The tool will delete the specified encrypted message from the database.

5. Export/Import Messages:
   Click the "Export Encrypted Messages" button to export all encrypted messages to a text file.
   To import encrypted messages from a text file, click the "Import Encrypted Messages" button and select the file containing the messages.

**_Note: Ensure that you have all dependencies installed before running the script._**
