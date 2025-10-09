#!/usr/bin/env python3
"""
aes192_cbc_file.py

Funciones para cifrar y descifrar archivos usando AES-192 en modo CBC con PKCS7 padding.

Formato del fichero cifrado:
    [IV (16 bytes)] + [ciphertext]

IMPORTANTE:
 - AES es un cifrado por bloques con tamaño de bloque 128 bits (16 bytes).
 - AES-192 usa una clave de 192 bits = 24 bytes.
 - Este ejemplo carga el archivo completo en memoria (útil para archivos pequeños/medianos).
   Para ficheros grandes se debe implementar chunking/streaming.
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# -----------------------------
# Función: cifrar con AES-192 CBC
# -----------------------------
def encrypt_file_aes_cbc_192(file_path: str, key: bytes, output_path: str = None):
    """
    Cifra un archivo usando AES-192 en modo CBC con padding PKCS7.

    :param file_path: ruta al archivo a cifrar
    :param key: clave de 24 bytes (192 bits)
    :param output_path: ruta opcional donde guardar el archivo cifrado
    :raises ValueError: si la clave no tiene 24 bytes
    """
    # Validación de la longitud de la clave
    if not isinstance(key, (bytes, bytearray)) or len(key) != 24:
        raise ValueError("La clave debe ser bytes con longitud 24 (192 bits) para AES-192.")

    # Comprobar existencia de fichero
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"No existe el archivo: {file_path}")

    # Leer todo el archivo (nota: para ficheros muy grandes ver recomendaciones abajo)
    plaintext = p.read_bytes()

    # Generar IV aleatorio (16 bytes) — debe ser único por cifrado con la misma clave
    iv = os.urandom(16)

    # Crear objeto Cipher (AES-192 + CBC)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Aplicar PKCS7 padding para que el total sea múltiplo del tamaño de bloque (128 bits)
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes
    padded = padder.update(plaintext) + padder.finalize()

    # Cifrar los datos
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # Preparar ruta de salida
    if not output_path:
        output_path = file_path + ".enc"

    # Guardar IV + ciphertext (IV no necesita ser secreto, pero sí único y almacenado)
    with open(output_path, "wb") as f:
        f.write(iv + ciphertext)

    # (opcional) intentar reducir tiempo de vida en memoria de variables sensibles
    # en Python no es garantía total, pero es una práctica recomendable
    try:
        del plaintext, padded
    except Exception:
        pass

    print(f"✅ Archivo cifrado: {output_path}")


# -----------------------------
# Función: descifrar AES-192 CBC
# -----------------------------
def decrypt_file_aes_cbc_192(encrypted_path: str, key: bytes, output_path: str = None):
    """
    Descifra un archivo cifrado por encrypt_file_aes_cbc_192.

    :param encrypted_path: ruta del archivo cifrado (IV + ciphertext)
    :param key: clave de 24 bytes (192 bits)
    :param output_path: ruta opcional donde guardar el archivo descifrado
    :raises ValueError: si la clave no tiene 24 bytes
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != 24:
        raise ValueError("La clave debe ser bytes con longitud 24 (192 bits) para AES-192.")

    p = Path(encrypted_path)
    if not p.is_file():
        raise FileNotFoundError(f"No existe el archivo: {encrypted_path}")

    # Leer fichero: primero 16 bytes -> IV, resto -> ciphertext
    data = p.read_bytes()
    if len(data) < 16:
        raise ValueError("Archivo cifrado inválido o truncado (menos de 16 bytes).")

    iv = data[:16]
    ciphertext = data[16:]

    # Crear objeto Cipher y descifrar
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Quitar padding PKCS7
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

    # Ruta de salida por defecto
    if not output_path:
        output_path = encrypted_path.replace(".enc", ".dec")

    with open(output_path, "wb") as f:
        f.write(plaintext)

    # (opcional) limpiar variables sensibles
    try:
        del decrypted_padded
    except Exception:
        pass

    print(f" Archivo descifrado: {output_path}")
