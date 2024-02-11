# Encrypt function
  Encrypts the given plain text using AES-256 encryption algorithm.

  Args:
  - plain_text (str): The plain text to be encrypted.
  - key (bytes): The encryption key.

  Returns:
  - bytes: The encrypted data.

  Raises:
  - None

# Decrypt function

  Decrypts AES-256 encrypted data using the provided key.

  Args:
  - encrypted_data (bytes): The encrypted data to be decrypted.
  - key (bytes): The key used for decryption.

  Returns:
  - str: The decrypted data as a string.

  Raises:
  - ValueError: If the encrypted data is invalid or the key is incorrect.


# Main fucntion
  Main function to test encryption and decryption using AES-256.

  This function presents a menu to the user with the following options:
  1. Encrypt string
  2. Decrypt string
  3. Exit

  The user can choose an option by entering the corresponding number.
  If the user chooses option 1, they will be prompted to enter a string to encrypt.
  A random 256-bit key will be generated and used for encryption.
  The encrypted string and encryption key will be displayed.
  If the user chooses option 2, they will be prompted to enter an encrypted string and encryption key.
  The string will be decrypted using the provided key and the decrypted string will be displayed.
  If the user chooses option 3, the program will exit.
