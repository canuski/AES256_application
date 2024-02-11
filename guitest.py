import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

DATABASE_FILE = "encrypted_messages.sqlite"


def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS encrypted_messages
                 (id INTEGER PRIMARY KEY, encrypted_message TEXT, encryption_key TEXT)''')
    conn.commit()
    conn.close()


def save_encrypted_message(encrypted_message, encryption_key):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO encrypted_messages (encrypted_message, encryption_key) VALUES (?, ?)",
              (encrypted_message, encryption_key))
    conn.commit()
    conn.close()


def get_encrypted_messages():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM encrypted_messages")
    messages = c.fetchall()
    conn.close()
    return messages


def delete_encrypted_message(message_id):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM encrypted_messages WHERE id=?", (message_id,))
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


class App:
    def __init__(self, master):
        self.master = master
        master.title("AES-256 Encryption/Decryption Tool")

        self.label = tk.Label(
            master, text="Welcome to the AES-256 Encryption/Decryption Tool!")
        self.label.pack()

        self.encrypt_button = tk.Button(
            master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(
            master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

        self.export_button = tk.Button(
            master, text="Export Encrypted Messages", command=self.export_messages)
        self.export_button.pack()

        self.import_button = tk.Button(
            master, text="Import Encrypted Messages", command=self.import_messages)
        self.import_button.pack()

        self.view_button = tk.Button(
            master, text="View Encrypted Messages", command=self.view_messages)
        self.view_button.pack()

        self.delete_button = tk.Button(
            master, text="Delete Encrypted Message", command=self.delete_message)
        self.delete_button.pack()

        self.exit_button = tk.Button(master, text="Exit", command=master.quit)
        self.exit_button.pack()

    def encrypt(self):
        self.new_window = tk.Toplevel(self.master)
        self.app = EncryptWindow(self.new_window)

    def decrypt(self):
        self.new_window = tk.Toplevel(self.master)
        self.app = DecryptWindow(self.new_window)

    def export_messages(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            messages = get_encrypted_messages()
            with open(filename, 'w') as file:
                for message in messages:
                    file.write(f"{message[0]},{message[1]},{message[2]}\n")
            messagebox.showinfo("Export Complete",
                                "Encrypted messages exported successfully.")

    def import_messages(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    parts = line.strip().split(',')
                    message_id = int(parts[0])
                    encrypted_message = parts[1]
                    encryption_key = parts[2]
                    save_encrypted_message(encrypted_message, encryption_key)
            messagebox.showinfo("Import Complete",
                                "Encrypted messages imported successfully.")

    def view_messages(self):
        messages = get_encrypted_messages()
        if messages:
            message_str = "\n".join(
                [f"ID: {message[0]}, Encrypted message: {message[1]}, Encryption key: {message[2]}" for message in messages])
            messagebox.showinfo("Encrypted Messages", message_str)
        else:
            messagebox.showinfo("Encrypted Messages",
                                "No encrypted messages found.")

    def delete_message(self):
        message_id = simpledialog.askinteger(
            "Delete Encrypted Message", "Enter the ID of the message you want to delete:")
        if message_id is not None:
            delete_encrypted_message(message_id)
            messagebox.showinfo(
                "Message Deleted", f"Encrypted message with ID {message_id} deleted successfully.")


class EncryptWindow:
    def __init__(self, master):
        self.master = master
        master.title("Encrypt Message")

        self.label = tk.Label(master, text="Enter your string to encrypt:")
        self.label.pack()

        self.entry = tk.Entry(master)
        self.entry.pack()

        self.encrypt_button = tk.Button(
            master, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.close_button = tk.Button(
            master, text="Close", command=master.destroy)
        self.close_button.pack()

    def encrypt_message(self):
        plaintext = self.entry.get()
        if plaintext:
            key = os.urandom(32)
            backend = default_backend()
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(
                key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            save_encrypted_message(ciphertext.hex(), key.hex())
            messagebox.showinfo(
                "Encrypted Message", f"Encrypted Message: {ciphertext.hex()}\nEncryption Key: {key.hex()}")
        else:
            messagebox.showerror("Error", "Please enter a string to encrypt.")


class DecryptWindow:
    def __init__(self, master):
        self.master = master
        master.title("Decrypt Message")

        self.label = tk.Label(
            master, text="Enter the ID of the message you want to decrypt:")
        self.label.pack()

        self.entry = tk.Entry(master)
        self.entry.pack()

        self.decrypt_button = tk.Button(
            master, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack()

        self.close_button = tk.Button(
            master, text="Close", command=master.destroy)
        self.close_button.pack()

    def decrypt_message(self):
        message_id = int(self.entry.get())
        messages = get_encrypted_messages()
        message_found = False
        for message in messages:
            if message[0] == message_id:
                message_found = True
                encrypted_message_hex, key_hex = message[1], message[2]
                encrypted_message = bytes.fromhex(encrypted_message_hex)
                key = bytes.fromhex(key_hex)
                backend = default_backend()
                iv = encrypted_message[:16]
                cipher = Cipher(algorithms.AES(
                    key), modes.CBC(iv), backend=backend)
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(
                    encrypted_message[16:]) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                unpadded_data = unpadder.update(
                    decrypted_data) + unpadder.finalize()
                messagebox.showinfo(
                    "Decrypted Message", f"Decrypted Message: {unpadded_data.decode()}")
                break
        if not message_found:
            messagebox.showerror(
                "Error", "Message with specified ID not found.")


def main():
    initialize_database()
    root = tk.Tk()
    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
