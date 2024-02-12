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
                 (id INTEGER PRIMARY KEY, name TEXT, encrypted_message TEXT, encryption_key TEXT)''')  # Updated table schema to include name
    conn.commit()
    conn.close()


# Modified to accept name
def save_encrypted_message(name, encrypted_message, encryption_key):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO encrypted_messages (name, encrypted_message, encryption_key) VALUES (?, ?, ?)",
              (name, encrypted_message, encryption_key))
    conn.commit()
    conn.close()


def get_encrypted_messages():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM encrypted_messages")
    messages = c.fetchall()
    conn.close()
    return messages


def delete_encrypted_message(name):  # Modified to accept name
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM encrypted_messages WHERE name=?", (name,))
    conn.commit()
    conn.close()


def encrypt_aes_256(plain_text, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


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


def delete_message():
    name = entry_delete_message_name.get()
    delete_encrypted_message(name)
    messagebox.showinfo("Message Deleted",
                        "Encrypted message deleted successfully.")


def view_saved_messages():
    messages = get_encrypted_messages()
    if messages:
        message_str = ""
        for message in messages:
            message_str += f"ID: {message[0]}, Name: {message[1]}, Encrypted message: {message[2]}, Encryption key: {message[3]}\n"
        messagebox.showinfo("Saved Encrypted Messages", message_str)
    else:
        messagebox.showinfo("No Messages", "No encrypted messages found.")


def encrypt_message():
    name = entry_message_name.get()  # Get the message name from the entry widget
    plain_text = entry_plain_text.get()
    key = os.urandom(32)
    encrypted_message = encrypt_aes_256(plain_text, key)
    # Save the name alongside the encrypted message
    save_encrypted_message(name, encrypted_message.hex(), key.hex())
    messagebox.showinfo(
        "Encrypted String", f"Encrypted String: {encrypted_message.hex()}\nEncryption Key: {key.hex()}")


def decrypt_message():
    name = entry_message_name.get()  # Get the message name from the entry widget
    messages = get_encrypted_messages()
    found = False
    for message in messages:
        if message[1] == name:
            found = True
            decrypted_message = decrypt_aes_256(
                bytes.fromhex(message[2]), bytes.fromhex(message[3]))
            messagebox.showinfo("Decrypted Message",
                                f"Decrypted message: {decrypted_message}")
            break
    if not found:
        messagebox.showerror("Error", "Message with specified name not found.")


def export_encrypted_messages():
    filename = filedialog.asksaveasfilename(
        defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if filename:
        messages = get_encrypted_messages()
        with open(filename, 'w') as file:
            for message in messages:
                file.write(
                    f"{message[0]},{message[1]},{message[2]},{message[3]}\n")
        messagebox.showinfo("Export Successful",
                            "Encrypted messages exported successfully.")


def import_encrypted_messages():
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, 'r') as file:
            lines = file.readlines()
            for line in lines:
                parts = line.strip().split(',')
                name = parts[1]
                encrypted_message = parts[2]
                encryption_key = parts[3]
                save_encrypted_message(name, encrypted_message, encryption_key)
        messagebox.showinfo("Import Successful",
                            "Encrypted messages imported successfully.")


initialize_database()

root = tk.Tk()
root.title("AES-256 Encryption/Decryption Tool")

bg_color = "#D1C4E9"
btn_bg_color = "#ffffff"
btn_fg_color = "#ab77e1"

root.configure(bg=bg_color)

label_message_name = tk.Label(
    root, text="Enter the name for this message:", bg=bg_color)  # Added label for message name
label_message_name.pack()

entry_message_name = tk.Entry(root)
entry_message_name.pack()

label_plain_text = tk.Label(
    root, text="Enter your string to encrypt and save:", bg=bg_color)
label_plain_text.pack()

entry_plain_text = tk.Entry(root)
entry_plain_text.pack()


button_encrypt = tk.Button(root, text="Encrypt and Save",
                           command=encrypt_message, bg=btn_bg_color, fg=btn_fg_color)
button_encrypt.pack()

button_decrypt = tk.Button(
    root, text="Decrypt", command=decrypt_message, bg=btn_bg_color, fg=btn_fg_color)
button_decrypt.pack()

button_export = tk.Button(root, text="Export Encrypted Messages",
                          command=export_encrypted_messages, bg=btn_bg_color, fg=btn_fg_color)
button_export.pack()

button_import = tk.Button(root, text="Import Encrypted Messages",
                          command=import_encrypted_messages, bg=btn_bg_color, fg=btn_fg_color)
button_import.pack()

button_view = tk.Button(root, text="View Saved Encrypted Messages",
                        command=view_saved_messages, bg=btn_bg_color, fg=btn_fg_color)
button_view.pack()

label_delete_message_name = tk.Label(
    root, text="Enter the name of the message you want to delete:", bg=bg_color)
label_delete_message_name.pack()

entry_delete_message_name = tk.Entry(root)
entry_delete_message_name.pack()

button_delete = tk.Button(root, text="Delete Encrypted Message",
                          command=delete_message, bg=btn_bg_color, fg=btn_fg_color)
button_delete.pack()

root.mainloop()
