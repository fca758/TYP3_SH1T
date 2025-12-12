from __future__ import annotations
from typing import Optional, Union
import binascii
import re
import secrets
import os
import json
from pathlib import Path
from datetime import datetime

from aes import AES
from rsa import RSA


rsa = RSA()
aesCBC = AES()
aesAlgoritmos = ["AES-128", "AES-192", "AES-256"]
bytes_req = {
    "AES-128": 16,
    "AES-192": 24,
    "AES-256": 32,
}

KEYS_DIR = Path("Keys")
KEYS_FILE = KEYS_DIR / "keys.txt"

def _ensure_rsa_keys():
    """Asegura que existan las claves RSA para el cifrado del archivo de claves."""
    keys_dir = KEYS_DIR
    pub_key_path = keys_dir / "public.pem"
    priv_key_path = keys_dir / "private.pem"

    if not keys_dir.exists():
        keys_dir.mkdir(parents=True)

    # Si no existen las claves RSA, generarlas
    if not (pub_key_path.exists() and priv_key_path.exists()):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        # Generar par de claves RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Guardar clave privada
        with open(priv_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Guardar clave pública
        with open(pub_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def _encrypt_keys_file():
    """Encripta el archivo keys.txt con RSA."""
    _ensure_rsa_keys()
    # Use hybrid encryption: AES-256 for the file, RSA to encrypt the small AES key+IV.
    if KEYS_FILE.exists():
        pub_key_path = KEYS_DIR / "public.pem"
        # Generate a random AES-256 key
        sym_key = secrets.token_bytes(32)
        # Use .enc suffix so AES module recognizes encrypted files
        aes_output = str(KEYS_FILE) + ".enc"
        # Encrypt the keys file with AES (CBC). AES.encriptar_archivo_AES returns the IV.
        iv = aesCBC.encriptar_archivo_AES(file_path=str(KEYS_FILE), modeAES="CBC", key=sym_key, key_length_bits=256, output_path=aes_output)

        # Store sym_key||iv in a temp file and encrypt that small blob with RSA
        tmp_sym = KEYS_DIR / ".tmp_sym.bin"
        with open(tmp_sym, "wb") as f:
            f.write(sym_key + iv)

        # Encrypt the symmetric key blob with RSA and save as .key
        rsa.encriptar_archivo_RSA(str(tmp_sym), str(pub_key_path), str(KEYS_FILE) + ".key")

        # Remove temporary symmetric key blob
        try:
            tmp_sym.unlink()
        except Exception:
            pass

def _decrypt_keys_file():
    """Desencripta el archivo keys.txt.enc con RSA."""
    _ensure_rsa_keys()
    # Expect hybrid files: keys.txt.aes (AES ciphertext) and keys.txt.key (RSA-encrypted symkey+iv)
    # Expect AES ciphertext at keys.txt.enc
    enc_aes = Path(str(KEYS_FILE) + ".enc")
    enc_key = Path(str(KEYS_FILE) + ".key")
    if enc_aes.exists() and enc_key.exists():
        priv_key_path = KEYS_DIR / "private.pem"
        tmp_sym = KEYS_DIR / ".tmp_sym.dec"
        # Decrypt the symmetric key blob to temp
        rsa.desencriptar_archivo_RSA(str(enc_key), str(priv_key_path), str(tmp_sym))

        # Read sym_key and iv
        data = tmp_sym.read_bytes()
        # Expect 32 bytes key + 16 bytes IV
        if len(data) < 48:
            # malformed
            try:
                tmp_sym.unlink()
            except Exception:
                pass
            return

        sym_key = data[:32]
        iv = data[32:48]

        # Decrypt AES ciphertext into KEYS_FILE
        aesCBC.desencriptar_archivo_AES(file_path=str(enc_aes), modeAES="CBC", key=sym_key, iv=iv, key_length_bits=256, output_path=str(KEYS_FILE))

        # Remove temporary symmetric plaintext
        try:
            tmp_sym.unlink()
        except Exception:
            pass

def store_key(key: bytes, iv: bytes, algorithm: str, mode: str):
    """Almacena una clave AES y su IV en el archivo encriptado keys.txt."""
    _ensure_rsa_keys()

    # Desencriptar archivo actual si existe
    if Path(str(KEYS_FILE) + ".enc").exists():
        _decrypt_keys_file()

    # Preparar entrada nueva
    key_entry = {
        "timestamp": datetime.now().isoformat(),
        "algorithm": algorithm,
        "mode": mode,
        "key": key.hex(),
        "iv": iv.hex() if iv else None
    }

    # Leer entradas existentes o crear lista nueva
    entries = []
    if KEYS_FILE.exists():
        with open(KEYS_FILE, "r") as f:
            content = f.read().strip()
            if content:
                try:
                    entries = json.loads(content)
                except json.JSONDecodeError:
                    # Si el archivo existe pero no es JSON válido, hacer backup
                    backup = KEYS_FILE.with_suffix(".txt.bak")
                    KEYS_FILE.rename(backup)

    # Evitar entradas duplicadas: si ya existe una entrada para la misma
    # (key, algorithm, mode) actualizamos su IV y timestamp en lugar de crear
    # una nueva. Esto evita confusión cuando el usuario vuelve a encriptar
    # y cambia sólo el IV.
    updated = False
    for e in entries:
        if e.get("key") == key_entry["key"] and e.get("algorithm") == algorithm and e.get("mode") == mode:
            e["iv"] = key_entry["iv"]
            e["timestamp"] = key_entry["timestamp"]
            updated = True
            break

    if not updated:
        entries.append(key_entry)

    # Guardar archivo actualizado
    with open(KEYS_FILE, "w") as f:
        json.dump(entries, f, indent=2)

    # Reencriptar archivo
    _encrypt_keys_file()

    # Borrar archivo sin encriptar
    if KEYS_FILE.exists():
        KEYS_FILE.unlink()

def get_stored_keys():
    """Recupera las claves almacenadas en el archivo encriptado keys.txt."""
    _ensure_rsa_keys()
    
    # Desencriptar archivo
    _decrypt_keys_file()
    
    entries = []
    if KEYS_FILE.exists():
        try:
            with open(KEYS_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    entries = json.loads(content)
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        finally:
            # Siempre borrar el archivo desencriptado después de leerlo
            KEYS_FILE.unlink()
    
    return entries

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



def encriptacionArchivo(input_file: str, output_file: Optional[str], mode: str, key, algorithm: str = None) -> Optional[bytes]:
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
 
    key_bytes_length = bytes_req.get(algorithm) * 8
    
    if key_bytes_length is None:
        raise NotSupportedAlgoritm(f"Algorithm '{algorithm}' is not supported")
    
    try:
        iv = aesCBC.encriptar_archivo_AES(file_path=input_file, modeAES=mode, key_length_bits=key_bytes_length, key=key_bytes, output_path=output_file)
    except AttributeError:
        print("[ENCRYPT] {algorithm}: Algoritmo no encontrado en el modulo AES - adapta a tu implementacion")
    
    store_key(key=key_bytes, iv=iv, algorithm=algorithm, mode=mode)
        
    # Devolver el IV si se generó (útil para la GUI). Si no se generó, devolver None.
    try:
        return iv
    except NameError:
        return None


def desencriptarArchivo(input_file: str, output_file: Optional[str], mode: str, key: str, iv: Optional[Union[str, bytes]] = None, algorithm: str = None) -> None:
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
                # Resolver IV: usar el IV proporcionado o buscarlo en el almacén
                iv_bytes = None
                if iv is None:
                    entries = get_stored_keys()
                    for e in entries:
                        if e.get("key") == (key_bytes.hex() if isinstance(key_bytes, (bytes, bytearray)) else key) and e.get("algorithm") == algorithm and e.get("mode") == mode:
                            iv_hex = e.get("iv")
                            if iv_hex:
                                iv_bytes = bytes.fromhex(iv_hex)
                                break
                else:
                    iv_bytes = bytes.fromhex(iv) if isinstance(iv, str) else iv

                if iv_bytes is None:
                    raise ValueError("IV no disponible para descifrar: proporciona el IV o selecciona la clave guardada asociada.")

                aesCBC.desencriptar_archivo_AES(file_path=input_file, modeAES=mode, key=key_bytes, key_length_bits=256, iv=iv_bytes, output_path=output_file)
                #aes256.decrypt_file_aes_cbc_256(input_file, key_bytes, output_file)
            except AttributeError:
                print("[DECRYPT] AES-256: decrypt_file_aes_cbc_256 not found on AES module — adapt to your implementation")

        case "AES-192":
            try:
                iv_bytes = None
                if iv is None:
                    entries = get_stored_keys()
                    for e in entries:
                        if e.get("key") == (key_bytes.hex() if isinstance(key_bytes, (bytes, bytearray)) else key) and e.get("algorithm") == algorithm and e.get("mode") == mode:
                            iv_hex = e.get("iv")
                            if iv_hex:
                                iv_bytes = bytes.fromhex(iv_hex)
                                break
                else:
                    iv_bytes = bytes.fromhex(iv) if isinstance(iv, str) else iv

                if iv_bytes is None:
                    raise ValueError("IV no disponible para descifrar: proporciona el IV o selecciona la clave guardada asociada.")

                aesCBC.desencriptar_archivo_AES(file_path=input_file, modeAES=mode, key=key_bytes, key_length_bits=192, iv=iv_bytes, output_path=output_file)
                #aes192.decrypt_file_aes_cbc_192(input_file, key_bytes, output_file)
            except AttributeError:
                print("[ENCRYPT] AES-256: Algoritmo AES-192 no encontrado en el modulo AES - adapta a tu implementacion")
        case "AES-128":
            try:
                iv_bytes = None
                if iv is None:
                    entries = get_stored_keys()
                    for e in entries:
                        if e.get("key") == (key_bytes.hex() if isinstance(key_bytes, (bytes, bytearray)) else key) and e.get("algorithm") == algorithm and e.get("mode") == mode:
                            iv_hex = e.get("iv")
                            if iv_hex:
                                iv_bytes = bytes.fromhex(iv_hex)
                                break
                else:
                    iv_bytes = bytes.fromhex(iv) if isinstance(iv, str) else iv

                if iv_bytes is None:
                    raise ValueError("IV no disponible para descifrar: proporciona el IV o selecciona la clave guardada asociada.")

                aesCBC.desencriptar_archivo_AES(file_path=input_file, modeAES=mode, key=key_bytes, iv=iv_bytes, key_length_bits=128, output_path=output_file)
                #aes128.decrypt_file_aes_cbc_128(input_file, key_bytes, output_file)
            except AttributeError:
                print("[ENCRYPT] AES-128: Algoritmo AES-128 no encontrado en el modulo AES - adapta a tu implementacion")





def generadorDeClave(algorithm: Optional[str]) -> bytes:
    if algorithm is None:
        raise NotSupportedAlgoritm("No algorithm specified")

    req_len = bytes_req.get(algorithm)
    if req_len is None:
        raise NotSupportedAlgoritm(f"Algorithm '{algorithm}' is not supported")

    # Generar clave aleatoria
    key = secrets.token_bytes(req_len)   


    return key



class NotSupportedAlgoritm(Exception):
    def __init__(self, *args):
        super().__init__(*args)