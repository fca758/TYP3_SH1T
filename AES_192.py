#!/usr/bin/env python3
"""
aes192_gcm_file_crypto.py

Cifra y descifra archivos usando AES-192 en modo GCM (AEAD).
Opciones:
 - Proveer una clave (hex, 24 bytes / 48 hex chars) o
 - Proveer una contraseña (se deriva la clave con scrypt).

Formato de archivo cifrado (simple y extensible):
 [MAGIC (8 bytes)] [FLAGS (1 byte)] [salt? (16 bytes if flags&1)] [nonce (12 bytes)] [ciphertext (rest)]

FLAGS: bit0 = 1 => salt presente (clave derivada de contraseña)
"""

import os
import argparse
import getpass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ----------------------------
# Constantes y parámetros
# ----------------------------
MAGIC = b'AES192G1'       # 8 bytes magic/version tag
FLAG_SALT = 0x01          # si está, significa que seguiremos salt + scrypt
SALT_LEN = 16             # longitud del salt en bytes
NONCE_LEN = 12            # recomendación NIST para GCM
KEY_LEN = 24              # AES-192 -> 24 bytes
SCRYPT_N = 2**14          # coste CPU/mem (ajustable)
SCRYPT_R = 8
SCRYPT_P = 1

# ----------------------------
# Utilidades
# ----------------------------
def derive_key_from_password(password: bytes, salt: bytes) -> bytes:
    """
    Deriva una clave de KEY_LEN bytes con scrypt a partir de una contraseña y un salt.
    Parámetros scrypt elegidos para equilibrio razonable en CPU/mem en máquinas modernas.
    """
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password)

def _zero_bytes(b: bytearray):
    """
    Intento de sobreescribir contenido sensible en memoria.
    En Python no es garantía absoluta, pero reduce tiempo de vida en memoria.
    """
    try:
        for i in range(len(b)):
            b[i] = 0
    except Exception:
        pass

# ----------------------------
# Función de cifrado (AES-192-GCM)
# ----------------------------
def encrypt_file_aes192_gcm(input_path: str, output_path: str,
                            key: Optional[bytes] = None,
                            password: Optional[str] = None,
                            associated_data: Optional[bytes] = None) -> None:
    """
    Cifra 'input_path' y escribe resultado en 'output_path'.
    - key: clave de 24 bytes (AES-192). Si se pasa, se usa directamente.
    - password: si se pasa en lugar de key, se deriva una clave con scrypt y se guarda el salt en el fichero.
    - associated_data: bytes opcionales que se autentican (AAD). Por ejemplo: nombre de fichero.
    """
    if (key is None) == (password is None):
        raise ValueError("Proveer exactamente una de: key (bytes, 24) OR password (str).")

    # Leer datos del archivo (nota: carga todo en memoria; para archivos enormes implementar chunking)
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    # Preparar clave (24 bytes)
    salt = None
    if password is not None:
        salt = os.urandom(SALT_LEN)
        derived_key = derive_key_from_password(password.encode('utf-8'), salt)
        aes_key = derived_key
    else:
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
            raise ValueError(f"Si pasas key, debe ser bytes de longitud {KEY_LEN}.")
        aes_key = bytes(key)

    # Preparar AEAD
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(NONCE_LEN)  # 12 bytes recomendado
    if associated_data is None:
        # por ejemplo, podemos usar el nombre original para AAD
        associated_data = os.path.basename(input_path).encode('utf-8')

    # Cifrar: AESGCM.encrypt devuelve ciphertext || tag (la librería lo concatena)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    # Construir header y escribir archivo:
    # [MAGIC][FLAGS][salt?][nonce][ciphertext]
    flags = 0
    header = bytearray()
    header += MAGIC
    if salt is not None:
        flags |= FLAG_SALT
    header += bytes([flags])
    if salt is not None:
        header += salt
    header += nonce

    with open(output_path, 'wb') as out:
        out.write(header)
        out.write(ciphertext)

    # intentar limpiar claves sensibles
    if password is not None:
        _zero_bytes(bytearray(derived_key))
    else:
        _zero_bytes(bytearray(aes_key))

    print(f"✅ Cifrado completado: {output_path}")

# ----------------------------
# Función de descifrado
# ----------------------------
def decrypt_file_aes192_gcm(input_path: str, output_path: str,
                            key: Optional[bytes] = None,
                            password: Optional[str] = None,
                            associated_data: Optional[bytes] = None) -> None:
    """
    Descifra un archivo producido por encrypt_file_aes192_gcm.
    - Si el fichero fue producido a partir de password (contiene salt), hay que pasar 'password'.
    - Si fue producido a partir de key, pasar la misma key.
    """
    with open(input_path, 'rb') as f:
        # Leer magic + flags
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Formato desconocido o fichero no producido por este programa.")
        flags_b = f.read(1)
        if len(flags_b) != 1:
            raise ValueError("Cabecera truncada.")
        flags = flags_b[0]

        salt = None
        if flags & FLAG_SALT:
            salt = f.read(SALT_LEN)
            if len(salt) != SALT_LEN:
                raise ValueError("Cabecera (salt) truncada.")

        nonce = f.read(NONCE_LEN)
        if len(nonce) != NONCE_LEN:
            raise ValueError("Cabecera (nonce) truncada.")

        ciphertext = f.read()  # resto del fichero

    # Preparar clave
    if salt is not None:
        if password is None:
            raise ValueError("Este fichero fue cifrado con contraseña; debes proporcionar 'password'.")
        aes_key = derive_key_from_password(password.encode('utf-8'), salt)
    else:
        if key is None:
            raise ValueError("Este fichero fue cifrado con clave directa; debes proporcionar 'key' (24 bytes).")
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
            raise ValueError(f"Si pasas key, debe ser bytes de longitud {KEY_LEN}.")
        aes_key = bytes(key)

    aesgcm = AESGCM(aes_key)
    if associated_data is None:
        associated_data = os.path.basename(output_path).encode('utf-8') if output_path else None
        # Nota: para descifrar correctamente por AAD debe usarse el mismo AAD que al cifrar.
        # En este ejemplo por defecto hemos usado basename(input_path) en cifrado, por eso
        # en escenarios reales conviene almacenar el AAD en la cabecera o usar un valor fijo.

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as e:
        raise ValueError("Error al descifrar: contraseña/clave incorrecta o integridad del fichero rota.") from e

    with open(output_path, 'wb') as out:
        out.write(plaintext)

    # limpiar
    if salt is not None:
        _zero_bytes(bytearray(aes_key))

    print(f"🔓 Descifrado completado: {output_path}")

# ----------------------------
# Pequeña CLI para probar
# ----------------------------
def _parse_args():
    p = argparse.ArgumentParser(description="AES-192 GCM file encrypt/decrypt (scrypt optional).")
    sub = p.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("enc", help="Cifrar archivo")
    enc.add_argument("infile", help="Archivo a cifrar")
    enc.add_argument("outfile", help="Archivo cifrado de salida")
    enc.add_argument("--key", help="Clave AES-192 en hex (48 hex chars). Si se omite, se usa --password o se generará una clave aleatoria.")
    enc.add_argument("--password", action="store_true", help="Pedir contraseña para derivar clave (scrypt).")

    dec = sub.add_parser("dec", help="Descifrar archivo")
    dec.add_argument("infile", help="Archivo cifrado")
    dec.add_argument("outfile", help="Archivo descifrado de salida")
    dec.add_argument("--key", help="Clave AES-192 en hex (48 hex chars).")
    dec.add_argument("--password", action="store_true", help="Pedir contraseña para derivar clave (scrypt).")

    return p.parse_args()

def main():
    args = _parse_args()

    if args.cmd == "enc":
        if args.key and args.password:
            raise SystemExit("No usar --key y --password al mismo tiempo.")
        if args.key:
            # validar hex
            kbytes = bytes.fromhex(args.key)
            if len(kbytes) != KEY_LEN:
                raise SystemExit(f"Clave incorrecta: debe ser {KEY_LEN} bytes (48 hex chars).")
            encrypt_file_aes192_gcm(args.infile, args.outfile, key=kbytes)
        elif args.password:
            pwd = getpass.getpass("Password (will not echo): ")
            encrypt_file_aes192_gcm(args.infile, args.outfile, password=pwd)
        else:
            # Generar clave aleatoria y mostrar al usuario (útil en pruebas)
            k = os.urandom(KEY_LEN)
            print("🔑 Clave aleatoria AES-192 (guárdala, la necesitas para descifrar):")
            print(k.hex())
            encrypt_file_aes192_gcm(args.infile, args.outfile, key=k)

    elif args.cmd == "dec":
        if args.key and args.password:
            raise SystemExit("No usar --key y --password al mismo tiempo.")
        if args.key:
            kbytes = bytes.fromhex(args.key)
            if len(kbytes) != KEY_LEN:
                raise SystemExit(f"Clave incorrecta: debe ser {KEY_LEN} bytes (48 hex chars).")
            decrypt_file_aes192_gcm(args.infile, args.outfile, key=kbytes)
        elif args.password:
            pwd = getpass.getpass("Password (will not echo): ")
            decrypt_file_aes192_gcm(args.infile, args.outfile, password=pwd)
        else:
            raise SystemExit("Para descifrar debe indicar --key o --password.")

if __name__ == "__main__":
    main()