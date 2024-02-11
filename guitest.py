import tkinter as tk
from tkinter import messagebox, filedialog
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

DATABASE_FILE = "encrypted_messages.sqlite"

# Function to initialize the database


def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS encrypted_messages
                 (id INTEGER PRIMARY KEY, encrypted_message TEXT, encryption_key TEXT)''')
    conn.commit()
    conn.close()

# Function to save an encrypted message to the database


def save_encrypted_message(encrypted_message, encryption_key):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO encrypted_messages (encrypted_message, encryption_key) VALUES (?, ?)",
              (encrypted_message, encryption_key))
    conn.commit()
    conn.close()

# Function to get encrypted messages from the database


def get_encrypted_messages():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM encrypted_messages")
    messages = c.fetchall()
    conn.close()
    return messages

# Function to delete an encrypted message from the database


def delete_encrypted_message(message_id):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM encrypted_messages WHERE id=?", (message_id,))
    conn.commit()
    conn.close()

# Function to encrypt a string using AES-256


def encrypt_aes_256(plain_text, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

# Function to decrypt a message from the database and display it


def decrypt_aes_256(encrypted_data, key):
    backend = default_backend()
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode()

# Function to delete an encrypted message


def delete_message():
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

# Create and pack widgets for encryption
label_plain_text = tk.Label(
    root, text="Enter your string to encrypt and save:")
label_plain_text.pack()

entry_plain_text = tk.Entry(root)
entry_plain_text.pack()

button_encrypt = tk.Button(
    root, text="Encrypt and Save", command=encrypt_message)
button_encrypt.pack()

# Create and pack widgets for decryption
label_message_id = tk.Label(
    root, text="Enter the ID of the message you want to decrypt:")
label_message_id.pack()

entry_message_id = tk.Entry(root)
entry_message_id.pack()

button_decrypt = tk.Button(root, text="Decrypt", command=decrypt_message)
button_decrypt.pack()

# Create and pack other buttons for additional options
button_export = tk.Button(
    root, text="Export Encrypted Messages", command=export_encrypted_messages)
button_export.pack()

button_import = tk.Button(
    root, text="Import Encrypted Messages", command=import_encrypted_messages)
button_import.pack()

button_view = tk.Button(
    root, text="View Saved Encrypted Messages", command=view_saved_messages)
button_view.pack()

# Create and pack widgets for deleting a message
label_delete_message_id = tk.Label(
    root, text="Enter the ID of the message you want to delete:")
label_delete_message_id.pack()

entry_delete_message_id = tk.Entry(root)
entry_delete_message_id.pack()

button_delete = tk.Button(
    root, text="Delete Encrypted Message", command=delete_message)
button_delete.pack()

# Start the Tkinter event loop
root.mainloop()
