import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# ==============================================================
# FUNCIONES DE CIFRADO Y DESCIFRADO CON AES-128 CBC
# ==============================================================

def encrypt_file_aes_cbc_128(file_path: str, key: bytes, output_path: str = None):
    """
    Cifra un archivo utilizando AES (128 bits) en modo CBC.

    Parámetros:
        file_path: ruta del archivo a cifrar.
        key: clave de 16 bytes (128 bits).
        output_path: ruta de salida opcional del archivo cifrado.

    El archivo cifrado se genera en formato:
        [IV (16 bytes)] + [datos cifrados]
    """
    if len(key) != 16:
        raise ValueError("La clave debe tener 16 bytes (128 bits) para AES-128.")

    backend = default_backend()
    iv = os.urandom(16)  # Vector de inicialización único por cifrado

    # Crear el objeto cifrador
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Leer los datos del archivo original
    with open(file_path, 'rb') as f:
        data = f.read()

    # Aplicar padding PKCS7 (AES usa bloques de 128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Cifrar los datos
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Guardar el archivo cifrado (IV + datos cifrados)
    if not output_path:
        output_path = file_path + ".enc"

    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)

    print(f"✅ Archivo cifrado correctamente: {output_path}")


def decrypt_file_aes_cbc_128(encrypted_path: str, key: bytes, output_path: str = None):
    """
    Descifra un archivo cifrado con AES-128 CBC.

    Parámetros:
        encrypted_path: ruta del archivo cifrado (.enc)
        key: clave de 16 bytes (128 bits)
        output_path: ruta opcional para guardar el archivo descifrado
    """
    if len(key) != 16:
        raise ValueError("La clave debe tener 16 bytes (128 bits) para AES-128.")

    backend = default_backend()

    with open(encrypted_path, 'rb') as f:
        iv = f.read(16)               # Leer IV (primeros 16 bytes)
        encrypted_data = f.read()     # Leer el resto del archivo (datos cifrados)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    # Descifrar y luego quitar el padding
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_padded) + unpadder.finalize()

    # Guardar archivo descifrado
    if not output_path:
        output_path = encrypted_path.replace('.enc', '.dec')

    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"🔓 Archivo descifrado correctamente: {output_path}")

