from __future__ import annotations
from typing import Optional, Union
import binascii
import re
import secrets

from aes import AES


aesCBC = AES()
aesAlgoritmos = ["AES-128", "AES-192", "AES-256"]
bytes_req = {
    "AES-128": 16,
    "AES-192": 24,
    "AES-256": 32,
}

def _normalize_key(key: Union[None, str, bytes], algorithm: str) -> bytes:
    if key is None:
        raise NotSupportedAlgoritm("No key provided")

    # Si la clave ya es bytes, la usamos directamente
    if isinstance(key, bytes):
        kb = key
    elif isinstance(key, str):
        # Si la cadena parece hexadecimal, intentamos decodificarla
        if re.fullmatch(r"[0-9a-fA-F]+", key) and len(key) % 2 == 0:
            try:
                kb = bytes.fromhex(key)
            except Exception:
                # Si no es hex, codificar a utf-8
                kb = key.encode("utf-8")
        else:
            # Si no es hex, codificar a utf-8
            kb = key.encode("utf-8")
    else:
        raise TypeError("Key must be str or bytes")

    # Validar longitud de la clave según el algoritmo
    req_len = bytes_req.get(algorithm)
    
    if req_len is None:
        # no se conoce el algoritmo - no validar la longitud aquí
        return kb

    if len(kb) != req_len:
        raise ValueError(f"Key length for {algorithm} must be {req_len} bytes; got {len(kb)} bytes")

    return kb



def encriptacionArchivo(input_file: str, output_file: Optional[str],mode: str, key, algorithm: str = None) -> None:
    # Basic logging
    print("[ENCRYPT] handler called")
    print(f"  input_file = {input_file}")
    print(f"  mode = {mode}")
    print(f"  key = {key}")
    print(f"  algorithm = {algorithm}")

    # Comprobar si el algoritmo es soportado
    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")

    
    # Normalizar bytes:
    # Esto significa que si la clave es una cadena hexadecimal, se convertirá a bytes.
    # Si es una cadena normal, se codificará en UTF-8.
    # Si ya es bytes, se deja como está.
    key_bytes = _normalize_key(key, algorithm)
 

    match algorithm:
        case "AES-256":
            try:

                aesCBC.encriptar_archivo_AES(file_path=input_file, modeAES=mode, key_length_bits=256, key=key_bytes, output_path=output_file)
                #aes256.decrypt_file_aes_cbc_256(input_file, key_bytes, output_file)
            except AttributeError:
                print("[DECRYPT] AES-256: decrypt_file_aes_cbc_256 not found on AES module — adapt to your implementation")

        case "AES-192":
            try:

                aesCBC.encriptar_archivo_AES(file_path=input_file,modeAES=mode, key=key_bytes, key_length_bits=192, output_path=output_file)
                #aes192.decrypt_file_aes_cbc_192(input_file, key_bytes, output_file)
            except AttributeError:
                print("[ENCRYPT] AES-256: Algoritmo AES-192 no encontrado en el modulo AES - adapta a tu implementacion")
        case "AES-128":
            try:

                aesCBC.encriptar_archivo_AES(file_path=input_file,modeAES=mode, key=key_bytes, key_length_bits=128, output_path=output_file)
                #aes128.decrypt_file_aes_cbc_128(input_file, key_bytes, output_file)
            except AttributeError:
                print("[ENCRYPT] AES-128: Algoritmo AES-128 no encontrado en el modulo AES - adapta a tu implementacion")



def desencriptarArchivo(input_file: str, output_file: Optional[str],mode: str, key:str, algorithm: str = None) -> None:
    # Basic logging
    print("[DECRYPT] handler called")
    print(f"  input_file = {input_file}")
    print(f"  mode = {mode}")
    print(f"  key = {key}")
    print(f"  algorithm = {algorithm}")


    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")

    # Normalizar bytes:
    # Esto significa que si la clave es una cadena hexadecimal, se convertirá a bytes.
    # Si es una cadena normal, se codificará en UTF-8.
    # Si ya es bytes, se deja como está.
    key_bytes = _normalize_key(key, algorithm)

    match algorithm:
        case "AES-256":
            try:

                aesCBC.desencriptar_archivo_AES(file_path=input_file, modeAES=mode, key=key_bytes, key_length_bits=256, output_path=output_file)
                #aes256.decrypt_file_aes_cbc_256(input_file, key_bytes, output_file)
            except AttributeError:
                print("[DECRYPT] AES-256: decrypt_file_aes_cbc_256 not found on AES module — adapt to your implementation")

        case "AES-192":
            try:

                aesCBC.desencriptar_archivo_AES(file_path=input_file, modeAES=mode, key=key_bytes, key_length_bits=192, output_path=output_file)
                #aes192.decrypt_file_aes_cbc_192(input_file, key_bytes, output_file)
            except AttributeError:
                print("[ENCRYPT] AES-256: Algoritmo AES-192 no encontrado en el modulo AES - adapta a tu implementacion")
        case "AES-128":
            try:

                aesCBC.desencriptar_archivo_AES(file_path=input_file, modeAES=mode, key=key_bytes, key_length_bits=128, output_path=output_file)
                #aes128.decrypt_file_aes_cbc_128(input_file, key_bytes, output_file)
            except AttributeError:
                print("[ENCRYPT] AES-128: Algoritmo AES-128 no encontrado en el modulo AES - adapta a tu implementacion")





def generadorDeClave(algorithm: Optional[str]) -> bytes:
    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")


    req_len = bytes_req.get(algorithm)
    if req_len is None:
        raise NotSupportedAlgoritm(f"Algorithm '{algorithm}' is not supported")

    key = secrets.token_bytes(req_len)
    hexk = binascii.hexlify(key).decode("utf-8")
    print(f"[KEYGEN] Generated key for {algorithm}: {hexk}")

    return key

def guardarClaveArchivo(key: str) -> None:

    file_path = "Keys\\keys.txt"
    with open(file_path, 'a') as f:
        f.write(key)
        f.write("\n")

class NotSupportedAlgoritm(Exception):
    def __init__(self, *args):
        super().__init__(*args)