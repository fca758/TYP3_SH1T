import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_file_aes_cbc_256(file_path: str, key: bytes, output_path: str = None):
    """
    Encrypts a file using AES CBC 256-bit encryption.

    :param file_path: Path to the input file
    :param key: 32-byte encryption key (AES-256)
    :param output_path: Optional path to save the encrypted file
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256.")

    backend = default_backend()
    iv = os.urandom(16)  # AES block size for CBC mode is 16 bytes

    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Read and pad the input file
    with open(file_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save IV + encrypted data to file
    if not output_path:
        output_path = file_path + '.enc'

    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)

    print(f"File encrypted successfully: {output_path}")




def decrypt_file_aes_cbc_256(encrypted_path: str, key: bytes, output_path: str = None):
    """
    Decrypts a file encrypted with AES CBC 256-bit encryption.

    :param encrypted_path: Path to the encrypted file
    :param key: 32-byte encryption key (AES-256)
    :param output_path: Optional path to save the decrypted file
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256.")

    backend = default_backend()

    with open(encrypted_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_padded) + unpadder.finalize()

    if not output_path:
        output_path = encrypted_path.replace('.enc', '.dec')

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"File decrypted successfully: {output_path}")

