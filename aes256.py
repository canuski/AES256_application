# Import the required libraries
import tkinter as tk
from tkinter import messagebox, filedialog
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Define the name of the database file
DATABASE_FILE = "encrypted_messages.sqlite"


def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS encrypted_messages
                 (id INTEGER PRIMARY KEY, encrypted_message TEXT, encryption_key TEXT)''')  # Create a table to store encrypted messages
    conn.commit()
    conn.close()  # Close the connection


def save_encrypted_message(encrypted_message, encryption_key):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO encrypted_messages (encrypted_message, encryption_key) VALUES (?, ?)",
              (encrypted_message, encryption_key))  # Insert the encrypted message and encryption key into the database
    conn.commit()
    conn.close()  # Close the connection


def get_encrypted_messages():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    # Retrieve all encrypted messages from the database
    c.execute("SELECT * FROM encrypted_messages")
    messages = c.fetchall()  # Fetch all the results
    conn.close()  # Close the connection
    return messages


def delete_encrypted_message(message_id):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    # Delete the encrypted message with the specified ID
    c.execute("DELETE FROM encrypted_messages WHERE id=?", (message_id,))
    conn.commit()
    conn.close()  # Close the connection


def encrypt_aes_256(plain_text, key):
    # Function to encrypt a string using AES-256
    backend = default_backend()  # Get the default backend
    # Generate a random 16-byte initialization vector, an iv is used because it adds randomness to the encryption
    iv = os.urandom(16)
    # Create a new AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()  # Create an encryptor object to encrypt the data

    # Create a padder object to pad the data, padding is required for CBC mode because it works with blocks of data
    padder = padding.PKCS7(128).padder()
    # Pad the data and finalize the padding
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Encrypt the padded data and finalize the encryption
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the iv and the encrypted data, the iv is needed to decrypt the data
    return iv + ciphertext


def decrypt_aes_256(encrypted_data, key):
    # Function to decrypt a message from the database and display it
    backend = default_backend()
    # Get the iv from the encrypted data, its the first 16 bytes
    iv = encrypted_data[:16]
    # Get the ciphertext from the encrypted data, its the rest of the bytes
    ciphertext = encrypted_data[16:]

    # Create a new AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()  # Create a decryptor object to decrypt the data

    # Decrypt the data and finalize the decryption
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Create an unpadder object to remove the padding
    unpadder = padding.PKCS7(128).unpadder()
    # Remove the padding and finalize the unpadding
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode()  # Return the decrypted data as a string


def delete_message():
    # Function to delete an encrypted message
    message_id = entry_delete_message_id.get()
    delete_encrypted_message(message_id)
    messagebox.showinfo("Message Deleted",
                        "Encrypted message deleted successfully.")

# Function to display saved encrypted messages


def view_saved_messages():
    messages = get_encrypted_messages()
    if messages:
        message_str = ""
        for message in messages:
            message_str += f"ID: {message[0]}, Encrypted message: {message[1]}, Encryption key: {message[2]}\n"
        messagebox.showinfo("Saved Encrypted Messages", message_str)
    else:
        messagebox.showinfo("No Messages", "No encrypted messages found.")

# Function to handle encryption button click


def encrypt_message():
    plain_text = entry_plain_text.get()
    key = os.urandom(32)
    encrypted_message = encrypt_aes_256(plain_text, key)
    save_encrypted_message(encrypted_message.hex(), key.hex())
    messagebox.showinfo(
        "Encrypted String", f"Encrypted String: {encrypted_message.hex()}\nEncryption Key: {key.hex()}")

# Function to handle decryption button click


def decrypt_message():
    message_id = entry_message_id.get()
    messages = get_encrypted_messages()
    found = False
    for message in messages:
        if message[0] == int(message_id):
            found = True
            decrypted_message = decrypt_aes_256(
                bytes.fromhex(message[1]), bytes.fromhex(message[2]))
            messagebox.showinfo("Decrypted Message",
                                f"Decrypted message: {decrypted_message}")
            break
    if not found:
        messagebox.showerror("Error", "Message with specified ID not found.")

# Function to export encrypted messages to a file


def export_encrypted_messages():
    filename = filedialog.asksaveasfilename(
        defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if filename:
        messages = get_encrypted_messages()
        with open(filename, 'w') as file:
            for message in messages:
                file.write(f"{message[0]},{message[1]},{message[2]}\n")
        messagebox.showinfo("Export Successful",
                            "Encrypted messages exported successfully.")

# Function to import encrypted messages from a file


def import_encrypted_messages():
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, 'r') as file:
            lines = file.readlines()
            for line in lines:
                parts = line.strip().split(',')
                message_id = int(parts[0])
                encrypted_message = parts[1]
                encryption_key = parts[2]
                save_encrypted_message(encrypted_message, encryption_key)
        messagebox.showinfo("Import Successful",
                            "Encrypted messages imported successfully.")


# Initialize the database when the application starts
initialize_database()

# Initialize the Tkinter application window
root = tk.Tk()
root.title("AES-256 Encryption/Decryption Tool")

# Define colors
bg_color = "#D1C4E9"
btn_bg_color = "#ffffff"
btn_fg_color = "#ab77e1"  # Black button text color

# Set background color
root.configure(bg=bg_color)

# Create and pack widgets for encryption
label_plain_text = tk.Label(
    root, text="Enter your string to encrypt and save:", bg=bg_color)
label_plain_text.pack()

entry_plain_text = tk.Entry(root)
entry_plain_text.pack()

button_encrypt = tk.Button(root, text="Encrypt and Save",
                           command=encrypt_message, bg=btn_bg_color, fg=btn_fg_color)
button_encrypt.pack()

# Create and pack widgets for decryption
label_message_id = tk.Label(
    root, text="Enter the ID of the message you want to decrypt:", bg=bg_color)
label_message_id.pack()

entry_message_id = tk.Entry(root)
entry_message_id.pack()

button_decrypt = tk.Button(
    root, text="Decrypt", command=decrypt_message, bg=btn_bg_color, fg=btn_fg_color)
button_decrypt.pack()

# Create and pack other buttons for additional options
button_export = tk.Button(root, text="Export Encrypted Messages",
                          command=export_encrypted_messages, bg=btn_bg_color, fg=btn_fg_color)
button_export.pack()

button_import = tk.Button(root, text="Import Encrypted Messages",
                          command=import_encrypted_messages, bg=btn_bg_color, fg=btn_fg_color)
button_import.pack()

button_view = tk.Button(root, text="View Saved Encrypted Messages",
                        command=view_saved_messages, bg=btn_bg_color, fg=btn_fg_color)
button_view.pack()

# Create and pack widgets for deleting a message
label_delete_message_id = tk.Label(
    root, text="Enter the ID of the message you want to delete:", bg=bg_color)
label_delete_message_id.pack()

entry_delete_message_id = tk.Entry(root)
entry_delete_message_id.pack()

button_delete = tk.Button(root, text="Delete Encrypted Message",
                          command=delete_message, bg=btn_bg_color, fg=btn_fg_color)
button_delete.pack()

# Start the Tkinter event loop
root.mainloop()
