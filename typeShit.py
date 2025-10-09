"""Main CLI scaffold for the TYP3_SH1T project.

This file implements an interactive terminal menu and an argparse entrypoint.
It provides placeholder handlers for future classes (encryption, decryption,
key generation, status). Calls to yet-to-be-created modules are commented where
they will be inserted.

"""

from __future__ import annotations

from typing import Optional, Union
import re
import AES
import AES_128
import AES_192


class NotSupportedAlgoritm(Exception):

    def __init__(self, *args):
        super().__init__(*args)

aes128 = AES_128
aes192 = AES_192
aes256 = AES

aesAlgoritmos = ["AES-128", "AES-192", "AES-256"]


def _normalize_key(key: Union[None, str, bytes], algorithm: str) -> bytes:
    """Return a bytes object of the correct length for the chosen algorithm.

    Accepts a bytes object, a UTF-8 string, or a hex string. Raises a
    ValueError or TypeError when the key is missing or the length is wrong.
    """
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



def encriptacionArchivo(input_file: Optional[str], output_file: Optional[str], key: bytes, algorithm: Optional[str] = None) -> None:
    """Placeholder: encrypt input_file and write to output_file using key.

    Replace the print statements with calls to your encryption class, e.g.:
        from Algoritmo_Simetrico.Cifrado import Cifrador
        cif = Cifrador(key)
        cif.encrypt_file(input_file, output_file)
    """

    # Basic logging
    print("[ENCRYPT] handler called")
    print(f"  inpsut_file = {input_file}")
    print(f"  output_file = {output_file}")
    print(f"  key = {key}")
    print(f"  algorithm = {algorithm}")

    # Validate algorithm
    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")

    # Dispatch by algorithm
    # normalize key to bytes of correct length for the algorithm
    key_bytes = _normalize_key(key, algorithm)

    if algorithm == "AES-256":
        # Use the AES module assigned to aes256. Expecting a function like
        # aes256.encrypt_file(input_path, output_path, key). Adapt if your
        # AES module exposes a different API (class-based, etc.).

        try:
            # AES.encrypt_file_aes_cbc_256 expects (file_path, key, output_path)
            aes256.encrypt_file_aes_cbc_256(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-256: Algoritmo AES-256 no encontrado en el modulo AES - adapta a tu implementacion")
    elif algorithm == "AES-128":
        # TODO: implement AES-128 branch
        # Example placeholder for future implementation:
        # from Algoritmo_Simetrico.Cifrado128 import Cifrador128
        # cif = Cifrador128(key)
        # cif.encrypt_file(input_file, output_file)
        try:
            # AES.encrypt_file_aes_cbc_256 expects (file_path, key, output_path)

            aes128.encrypt_file_aes_cbc_128(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-128: Algoritmo AES-128 no encontrado en el modulo AES - adapta a tu implementacion")
    elif algorithm == "AES-192":
        # TODO: implement AES-192 branch
        try:
            # AES.encrypt_file_aes_cbc_256 expects (file_path, key, output_path)
            aes192.encrypt_file_aes_cbc_192(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-256: Algoritmo AES-192 no encontrado en el modulo AES - adapta a tu implementacion")
    else:
        raise NotSupportedAlgoritm(f"Algorithm '{algorithm}' is not supported")


def desencriptarArchivo(input_file: Optional[str], output_file: Optional[str], key: Optional[str], algorithm: Optional[str] = None) -> None:
    """Placeholder: decrypt input_file and write to output_file using key.

    Future implementation example:
        from Algoritmo_Simetrico.Descifrado import Descifrador
        dec = Descifrador(key)
        dec.decrypt_file(input_file, output_file)
    """
    # Basic logging
    print("[DECRYPT] handler called")
    print(f"  input_file = {input_file}")
    print(f"  output_file = {output_file}")
    print(f"  key = {key}")
    print(f"  algorithm = {algorithm}")

    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")

    # normalize key
    key_bytes = _normalize_key(key, algorithm)

    if algorithm == "AES-256":
        try:
            # AES.decrypt_file_aes_cbc_256 expects (encrypted_path, key, output_path)
            aes256.decrypt_file_aes_cbc_256(input_file, key_bytes, output_file)
        except AttributeError:
            print("[DECRYPT] AES-256: decrypt_file_aes_cbc_256 not found on AES module — adapt to your implementation")
    elif algorithm == "AES-128":
        # TODO: implement AES-128 branch
        # Example placeholder for future implementation:
        # from Algoritmo_Simetrico.Cifrado128 import Cifrador128
        # cif = Cifrador128(key)
        # cif.encrypt_file(input_file, output_file)
        try:
            # AES.encrypt_file_aes_cbc_256 expects (file_path, key, output_path)

            aes128.decrypt_file_aes_cbc_128(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-128: Algoritmo AES-128 no encontrado en el modulo AES - adapta a tu implementacion")
    elif algorithm == "AES-192":
        # TODO: implement AES-192 branch
        try:
            # AES.encrypt_file_aes_cbc_256 expects (file_path, key, output_path)
            aes192.decrypt_file_aes_cbc_192(input_file, key_bytes, output_file)
        except AttributeError:
            print("[ENCRYPT] AES-256: Algoritmo AES-192 no encontrado en el modulo AES - adapta a tu implementacion")
    else:
        raise NotSupportedAlgoritm(f"Algorithm '{algorithm}' is not supported")

def generadorDeClave(algorithm: Optional[str]) -> None:
    """Placeholder: generate a key for the selected algorithm.

    Future example:
        from Algoritmo_Simetrico.Keygen import KeyGenerator
        kg = KeyGenerator(algorithm)
        print(kg.generate())
    """
    print("[KEYGEN] Placeholder handler called")
    print(f"  algorithm = {algorithm}")

