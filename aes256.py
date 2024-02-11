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


def decrypt_and_display_message(message_id):
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM encrypted_messages WHERE id=?", (message_id,))
    row = c.fetchone()
    conn.close()
    if row:
        encrypted_message_hex, key_hex = row[1], row[2]
        encrypted_message = bytes.fromhex(encrypted_message_hex)
        key = bytes.fromhex(key_hex)
        decrypted_message = decrypt_aes_256(encrypted_message, key)
        print("Decrypted message:", decrypted_message)
    else:
        print("Message with specified ID not found.")


def export_encrypted_messages(filename):
    messages = get_encrypted_messages()
    with open(filename, 'w') as file:
        for message in messages:
            file.write(f"{message[0]},{message[1]},{message[2]}\n")
    print("Encrypted messages exported successfully.")


def import_encrypted_messages(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines:
            parts = line.strip().split(',')
            message_id = int(parts[0])
            encrypted_message = parts[1]
            encryption_key = parts[2]
            save_encrypted_message(encrypted_message, encryption_key)
    print("Encrypted messages imported successfully.")


def main():
    initialize_database()
    print("Welcome to the AES-256 Encryption/Decryption tool!\n")
    while True:
        print("1. Encrypt and save string")
        print("2. Decrypt string from database")
        print("3. Export encrypted messages")
        print("4. Import encrypted messages")
        print("5. View saved encrypted messages")
        print("6. Delete encrypted message")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            last_name = input("Enter your string to encrypt and save: ")
            key = os.urandom(32)
            encrypted_message = encrypt_aes_256(last_name, key)
            save_encrypted_message(encrypted_message.hex(), key.hex())
            print("Encrypted string:", encrypted_message.hex())
            print("Encryption Key:", key.hex())
        elif choice == "2":
            message_id = input(
                "Enter the ID of the message you want to decrypt: ")
            decrypt_and_display_message(message_id)
        elif choice == "3":
            filename = input(
                "Enter the filename to export encrypted messages: ")
            export_encrypted_messages(filename)
        elif choice == "4":
            filename = input(
                "Enter the filename to import encrypted messages: ")
            import_encrypted_messages(filename)
        elif choice == "5":
            print("Saved encrypted messages:")
            messages = get_encrypted_messages()
            for message in messages:
                print(
                    f"ID: {message[0]}, Encrypted message: {message[1]}, Encryption key: {message[2]}")
        elif choice == "6":
            message_id = input(
                "Enter the ID of the message you want to delete: ")
            delete_encrypted_message(message_id)
            print("Encrypted message deleted successfully.")
        elif choice == "7":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()
