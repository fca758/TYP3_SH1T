from __future__ import annotations

from typing import Optional, Union
import re
import AES_256
import AES_128
import AES_192



aes128 = AES_128
aes192 = AES_192
aes256 = AES_256

aesAlgoritmos = ["AES-128", "AES-192", "AES-256"]


def _normalize_key(key: Union[None, str, bytes], algorithm: str) -> bytes:
    if key is None:
        raise NotSupportedAlgoritm("No key provided")

    # If key is already bytes, keep it
    if isinstance(key, bytes):
        kb = key
    elif isinstance(key, str):
        # If the string looks like hex, try to decode it
        if re.fullmatch(r"[0-9a-fA-F]+", key) and len(key) % 2 == 0:
            try:
                kb = bytes.fromhex(key)
            except Exception:
                # Fallback to raw utf-8 encoding
                kb = key.encode("utf-8")
        else:
            kb = key.encode("utf-8")
    else:
        raise TypeError("Key must be str or bytes")

    required = {
        "AES-128": 16,
        "AES-192": 24,
        "AES-256": 32,
    }
    req_len = required.get(algorithm)
    if req_len is None:
        # unknown algorithm - don't validate length here
        return kb

    if len(kb) != req_len:
        raise ValueError(f"Key length for {algorithm} must be {req_len} bytes; got {len(kb)} bytes")

    return kb



def encriptacionArchivo(input_file: Optional[str], output_file: Optional[str], key: str, algorithm: Optional[str] = None) -> None:
    # Basic logging
    print("[ENCRYPT] handler called")
    print(f"  inpsut_file = {input_file}")
    print(f"  output_file = {output_file}")
    print(f"  key = {key}")
    print(f"  algorithm = {algorithm}")

    # Comprobar si el algoritmo es soportado
    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")

    
    # Normalizar Clave
#    key_bytes = key.encode('utf-8')
#
#    req_len = {
#        "AES-128": 16,
#        "AES-192": 24,
#        "AES-256": 32,
#    }
#
#    if len(key_bytes) != req_len[algorithm]:
#        raise ValueError(f"Key length for {algorithm} must be {req_len[algorithm]} bytes; got {len(key_bytes)} bytes")
    
    key_bytes = _normalize_key(key, algorithm)

    if algorithm == "AES-256":
        try:

            aes256.encrypt_file_aes_cbc_256(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-256: Algoritmo AES-256 no encontrado en el modulo AES - adapta a tu implementacion")
    elif algorithm == "AES-128":
        try:

            aes128.encrypt_file_aes_cbc_128(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-128: Algoritmo AES-128 no encontrado en el modulo AES - adapta a tu implementacion")
    elif algorithm == "AES-192":
        try:

            aes192.encrypt_file_aes_cbc_192(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-256: Algoritmo AES-192 no encontrado en el modulo AES - adapta a tu implementacion")
    else:
        raise NotSupportedAlgoritm(f"Algorithm '{algorithm}' is not supported")


def desencriptarArchivo(input_file: Optional[str], output_file: Optional[str], key: Optional[str], algorithm: Optional[str] = None) -> None:
    # Basic logging
    print("[DECRYPT] handler called")
    print(f"  input_file = {input_file}")
    print(f"  output_file = {output_file}")
    print(f"  key = {key}")
    print(f"  algorithm = {algorithm}")

    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")

    # Normalizar Clave
    key_bytes = key.encode('utf-8')

    if algorithm == "AES-256":
        try:

            aes256.decrypt_file_aes_cbc_256(input_file, key_bytes, output_file)
        except AttributeError:
            print("[DECRYPT] AES-256: decrypt_file_aes_cbc_256 not found on AES module — adapt to your implementation")
    elif algorithm == "AES-128":
        try:

            aes128.decrypt_file_aes_cbc_128(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-128: Algoritmo AES-128 no encontrado en el modulo AES - adapta a tu implementacion")
    elif algorithm == "AES-192":

        try:
            aes192.decrypt_file_aes_cbc_192(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-256: Algoritmo AES-192 no encontrado en el modulo AES - adapta a tu implementacion")
    else:
        raise NotSupportedAlgoritm(f"Algorithm '{algorithm}' is not supported")



def generadorDeClave(algorithm: Optional[str]) -> bytes:
    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")

    import os
    import binascii

    required = {
        "AES-128": 16,
        "AES-192": 24,
        "AES-256": 32,
    }

    req_len = required.get(algorithm)
    if req_len is None:
        raise NotSupportedAlgoritm(f"Algorithm '{algorithm}' is not supported")

    key = os.urandom(req_len)
    hexk = binascii.hexlify(key).decode('utf-8')
    print(f"[KEYGEN] Generated key for {algorithm}: {hexk}")
    # Return raw bytes so callers (GUI or CLI) can use or display as they prefer
    return key


class NotSupportedAlgoritm(Exception):
    def __init__(self, *args):
        super().__init__(*args)