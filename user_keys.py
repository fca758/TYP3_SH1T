"""
Módulo para gestión de claves AES por usuario.

Cada usuario puede almacenar sus propias claves AES cifradas con su clave privada.
Las claves se almacenan en certs/user_keys/<usuario>_keys.enc
"""

from pathlib import Path
import json
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.backends import default_backend
import certificacion

USER_KEYS_DIR = Path("certs/user_keys")


def _ensure_dirs():
    """Asegurar que existe el directorio de claves de usuario"""
    USER_KEYS_DIR.mkdir(parents=True, exist_ok=True)


def _get_user_keys_file(identity: str) -> Path:
    """Obtiene la ruta del archivo de claves del usuario"""
    fn = certificacion._safe_filename(identity)
    return USER_KEYS_DIR / f"{fn}_keys.enc"


def store_user_key(identity: str, password: str, key: bytes, iv: bytes, 
                   algorithm: str, mode: str, filename: str = None):
    """
    Almacena una clave AES para un usuario específico.
    
    Args:
        identity: Identidad del usuario
        password: Contraseña del usuario para cifrar las claves
        key: Clave AES a almacenar
        iv: IV usado con la clave
        algorithm: Algoritmo (ej: "AES-256")
        mode: Modo (ej: "CBC")
        filename: Nombre del archivo asociado (opcional)
    """
    _ensure_dirs()
    
    # Cargar claves existentes o crear nueva lista
    try:
        keys = get_user_keys(identity, password) or []
    except FileNotFoundError:
        keys = []
    except Exception as e:
        # Si hay error descifrando (contraseña incorrecta), lanzar error
        raise ValueError(f"Error al acceder a claves existentes: {e}")
    
    # Añadir nueva clave
    from datetime import datetime
    keys.append({
        "timestamp": datetime.now().isoformat(),
        "algorithm": algorithm,
        "mode": mode,
        "key": key.hex(),
        "iv": iv.hex(),
        "filename": filename or "Sin nombre"
    })
    
    # Cifrar y guardar
    _encrypt_user_keys(identity, password, keys)


def get_user_keys(identity: str, password: str) -> list:
    """
    Obtiene las claves AES de un usuario.
    
    Args:
        identity: Identidad del usuario
        password: Contraseña del usuario
        
    Returns:
        Lista de diccionarios con las claves almacenadas
        
    Raises:
        FileNotFoundError: Si no existen claves para el usuario
        ValueError: Si la contraseña es incorrecta
    """
    keys_file = _get_user_keys_file(identity)
    if not keys_file.exists():
        raise FileNotFoundError(f"No hay claves guardadas para {identity}")
    
    # Descifrar con la clave privada del usuario
    return _decrypt_user_keys(identity, password)


def _encrypt_user_keys(identity: str, password: str, keys: list):
    """Cifra las claves del usuario con derivación de su clave privada"""
    # Obtener clave privada del usuario (esto valida la contraseña)
    user_priv = certificacion._decrypt_user_private_key(identity, password)
    
    # Serializar claves a JSON
    keys_json = json.dumps(keys, indent=2).encode('utf-8')
    
    # Generar IV
    iv = secrets.token_bytes(16)
    
    # Derivar clave AES desde la clave privada (usar hash)
    key_material = user_priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    aes_key = hashlib.sha256(key_material).digest()
    
    # Cifrar
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding
    padder = padding.PKCS7(128).padder()
    padded = padder.update(keys_json) + padder.finalize()
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Guardar: iv || ciphertext
    keys_file = _get_user_keys_file(identity)
    keys_file.write_bytes(iv + ciphertext)


def _decrypt_user_keys(identity: str, password: str) -> list:
    """Descifra las claves del usuario"""
    keys_file = _get_user_keys_file(identity)
    data = keys_file.read_bytes()
    
    iv = data[:16]
    ciphertext = data[16:]
    
    # Obtener clave privada del usuario (esto valida la contraseña)
    user_priv = certificacion._decrypt_user_private_key(identity, password)
    
    # Derivar clave AES
    key_material = user_priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    aes_key = hashlib.sha256(key_material).digest()
    
    # Descifrar
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpadding
    unpadder = padding.PKCS7(128).unpadder()
    keys_json = unpadder.update(padded) + unpadder.finalize()
    
    return json.loads(keys_json.decode('utf-8'))


def delete_user_key(identity: str, password: str, index: int):
    """
    Elimina una clave específica del almacén del usuario.
    
    Args:
        identity: Identidad del usuario
        password: Contraseña del usuario
        index: Índice de la clave a eliminar (0-based)
    """
    keys = get_user_keys(identity, password)
    
    if 0 <= index < len(keys):
        keys.pop(index)
        _encrypt_user_keys(identity, password, keys)
    else:
        raise IndexError(f"Índice {index} fuera de rango")


def has_stored_keys(identity: str) -> bool:
    """Verifica si un usuario tiene claves almacenadas"""
    keys_file = _get_user_keys_file(identity)
    return keys_file.exists()
