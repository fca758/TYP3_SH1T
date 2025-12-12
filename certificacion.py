from pathlib import Path
import json
import secrets
import base64
import hashlib
import tempfile
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Asegúrate de que el módulo aes.py esté en la misma carpeta
from aes import AES

AES_MODULE = AES()

# --- CONFIGURACIÓN DE RUTAS ---
ROOT = Path("certs")
USERS_DIR = ROOT / "users"
CA_DIR = ROOT / "ca"
# Aquí definimos obligatoriamente el archivo de licencia en texto plano
LICENSE_FILE = ROOT / "license.txt"

SEPARATOR = b"\n---CERTMETA-END---\n"

def _ensure_dirs():
    for d in (ROOT, USERS_DIR, CA_DIR):
        if not d.exists():
            d.mkdir(parents=True)

def _safe_filename(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()

def get_license_key() -> bytes:
    """
    Lee la clave AES de 32 bytes (256 bits) desde license.txt en formato hexadecimal.
    Si el archivo no existe, lanza un error.
    """
    _ensure_dirs()
    if not LICENSE_FILE.exists():
        raise FileNotFoundError(f"Falta el archivo de licencia en: {LICENSE_FILE}. Crea el archivo txt con la clave AES en formato hexadecimal (64 caracteres).")
    
    # Leer el contenido en formato hexadecimal y convertir a bytes
    hex_key = LICENSE_FILE.read_text(encoding="utf-8").strip()
    try:
        key = bytes.fromhex(hex_key)
        if len(key) != 32:
            raise ValueError(f"La clave debe ser de 32 bytes (256 bits = 64 caracteres hex). Encontrados: {len(key)} bytes")
        return key
    except ValueError as e:
        raise ValueError(f"Error leyendo la clave AES desde {LICENSE_FILE}: {e}. Debe contener 64 caracteres hexadecimales.")
    
    # Leer el contenido en formato hexadecimal y convertir a bytes
    hex_key = LICENSE_FILE.read_text(encoding="utf-8").strip()
    try:
        key = bytes.fromhex(hex_key)
        if len(key) != 32:
            raise ValueError(f"La clave debe ser de 32 bytes (256 bits). Encontrados: {len(key)} bytes")
        return key
    except ValueError as e:
        raise ValueError(f"Error leyendo la clave desde {LICENSE_FILE}: {e}")


def has_ca() -> bool:
    """Return True if CA public and private files exist."""
    pub = CA_DIR / "ca_public.pem"
    priv = CA_DIR / "ca_private.enc"
    return pub.exists() and priv.exists()

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    # PBKDF2 with reasonable iterations
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend())
    return kdf.derive(password.encode("utf-8"))


def create_ca(aes_key_hex: str = None, key_size: int = 2048) -> None:
    """
    Genera clave RSA de la autoridad (CA).
    Guarda la clave AES en 'certs/license.txt' en formato hexadecimal y la usa para cifrar la clave privada de la CA.
    
    Parámetros:
        aes_key_hex (str, opcional): Clave AES de 32 bytes en formato hexadecimal (64 caracteres).
                                      Si no se proporciona, se genera una aleatoria.
        key_size (int): Tamaño de la clave RSA en bits (default: 2048)
    """
    _ensure_dirs()
    priv_path = CA_DIR / "ca_private.enc"
    pub_path = CA_DIR / "ca_public.pem"

    # Si ya existe CA, eliminarla primero para recrearla
    if has_ca():
        print("⚠ Ya existe una CA. Eliminándola para crear una nueva...")
        try:
            priv_path.unlink()
            pub_path.unlink()
        except Exception as e:
            print(f"⚠ Error eliminando CA anterior: {e}")

    # Lógica de la clave AES:
    # Si el archivo ya existe, usamos esa clave. Si no, generamos/usamos la proporcionada.
    if LICENSE_FILE.exists():
        print("INFO: Usando clave AES existente de license.txt")
        aes_key = get_license_key()
    else:
        if aes_key_hex:
            # Validar la clave proporcionada
            try:
                aes_key = bytes.fromhex(aes_key_hex)
                if len(aes_key) != 32:
                    raise ValueError(f"La clave AES debe ser de 32 bytes (64 caracteres hex). Proporcionados: {len(aes_key)} bytes")
            except ValueError as e:
                raise ValueError(f"Error en la clave AES proporcionada: {e}")
        else:
            # Generar clave aleatoria de 32 bytes (256 bits)
            aes_key = secrets.token_bytes(32)
            print("INFO: Se generó una nueva clave AES aleatoria.")
        
        # Guardar la clave en formato hexadecimal
        LICENSE_FILE.write_text(aes_key.hex(), encoding="utf-8")
        print(f"Clave AES guardada en: {LICENSE_FILE}")

    # Generate RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    # Serialize public
    pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_path.write_bytes(pub_pem)

    # Serialize private to temp file
    tf_path = Path(tempfile.gettempdir()) / f"ca_priv_{secrets.token_hex(8)}.pem"
    
    try:
        tf_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PrivateFormat.PKCS8, 
                encryption_algorithm=serialization.NoEncryption()
            )
        )

        # Encrypt private using AES-256 with the key from license.txt
        iv = AES_MODULE.encriptar_archivo_AES(
            file_path=str(tf_path), 
            modeAES="CBC", 
            key=aes_key, 
            key_length_bits=256, 
            output_path=str(tf_path) + ".enc"
        )

        # Read ciphertext and write final file as iv||ciphertext
        ciphertext = Path(str(tf_path) + ".enc").read_bytes()
        priv_path.write_bytes(iv + ciphertext)
        
        print(f"CA creada correctamente.")
        
    finally:
        # Cleanup temps
        try:
            if tf_path.exists():
                tf_path.unlink()
        except Exception:
            pass
        try:
            enc_path = Path(str(tf_path) + ".enc")
            if enc_path.exists():
                enc_path.unlink()
        except Exception:
            pass


def _ensure_ca_exists():
    """
    Verifica que exista la CA. Si no existe, la crea automáticamente.
    """
    if not has_ca():
        print("⚠ No se encontró la CA. Creando una nueva automáticamente...")
        try:
            create_ca()
            print("✓ CA creada automáticamente.")
        except Exception as e:
            raise RuntimeError(f"No se pudo crear la CA automáticamente: {e}")


def _load_ca_public() -> serialization.PublicFormat:
    """Carga la clave pública de la CA. Si no existe, crea la CA automáticamente."""
    _ensure_ca_exists()
    pub_path = CA_DIR / "ca_public.pem"
    return serialization.load_pem_public_key(pub_path.read_bytes(), backend=default_backend())


def _load_ca_private():
    """
    Carga la clave privada de la CA. Si no existe, crea la CA automáticamente.
    Usa la clave AES almacenada en license.txt para descifrar ca_private.enc.
    """
    _ensure_ca_exists()
    priv_path = CA_DIR / "ca_private.enc"

    data = priv_path.read_bytes()
    iv = data[:16]
    ciphertext = data[16:]

    # write ciphertext to temp .enc file for AES module
    tmp_enc = Path(tempfile.gettempdir()) / f"ca_priv_dec_{secrets.token_hex(8)}.enc"
    tmp_out = Path(tempfile.gettempdir()) / f"ca_priv_dec_{secrets.token_hex(8)}.dec"

    try:
        tmp_enc.write_bytes(ciphertext)

        # Obtener la clave AES directamente desde license.txt (sin derivar)
        aes_key = get_license_key()
        
        # Decrypt to temp plaintext
        AES_MODULE.desencriptar_archivo_AES(
            file_path=str(tmp_enc), 
            modeAES="CBC", 
            key=aes_key, 
            iv=iv, 
            key_length_bits=256, 
            output_path=str(tmp_out)
        )

        priv = serialization.load_pem_private_key(tmp_out.read_bytes(), password=None, backend=default_backend())
        
        return priv
        
    finally:
        # Cleanup
        try:
            if tmp_enc.exists():
                tmp_enc.unlink()
        except Exception:
            pass
        try:
            if tmp_out.exists():
                tmp_out.unlink()
        except Exception:
            pass


def create_user(identity: str, password: str, key_size: int = 2048) -> None:
    """
    Genera par RSA para usuario, crea certificado firmado por CA.
    La clave privada del usuario se cifra con una clave derivada de su password.
    Si no existe la CA, se crea automáticamente.
    """
    _ensure_dirs()
    fn = _safe_filename(identity)
    user_cert_path = USERS_DIR / f"{fn}.cert"
    user_key_path = USERS_DIR / f"{fn}.key.enc"

    # Generate user key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    ident_bytes = identity.encode("utf-8")

    # Sign with CA private (se crea automáticamente si no existe)
    ca_priv = _load_ca_private()

    signature = ca_priv.sign(pub_pem + ident_bytes, padding.PKCS1v15(), hashes.SHA256())

    cert = {
        "identity": identity,
        "public_key_pem": pub_pem.decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8")
    }

    with open(user_cert_path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2)

    # Store private key encrypted with password-derived key (with salt)
    salt = secrets.token_bytes(16)
    key = _derive_key_from_password(password, salt)

    # Crear archivo temporal con un nombre único
    tf_path = Path(tempfile.gettempdir()) / f"userkey_{secrets.token_hex(8)}.pem"
    
    try:
        # Escribir la clave privada en el archivo temporal
        tf_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PrivateFormat.PKCS8, 
                encryption_algorithm=serialization.NoEncryption()
            )
        )

        # Encriptar el archivo temporal - esto devuelve el IV
        iv = AES_MODULE.encriptar_archivo_AES(
            file_path=str(tf_path), 
            modeAES="CBC", 
            key=key, 
            key_length_bits=256, 
            output_path=str(tf_path) + ".enc"
        )

        # Leer el ciphertext del archivo encriptado (sin IV en cabecera)
        ciphertext = Path(str(tf_path) + ".enc").read_bytes()

        # Final file structure: salt(16) || iv(16) || ciphertext
        user_key_path.write_bytes(salt + iv + ciphertext)
            
        print(f"Usuario '{identity}' creado correctamente.")
        
    finally:
        # Limpiar archivos temporales
        try:
            if tf_path.exists():
                tf_path.unlink()
        except Exception:
            pass
        try:
            enc_path = Path(str(tf_path) + ".enc")
            if enc_path.exists():
                enc_path.unlink()
        except Exception:
            pass


def list_certificates():
    _ensure_dirs()
    certs = []
    for p in USERS_DIR.glob("*.cert"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                cert = json.load(f)
            # Try to verify; if invalid, mark as invalid
            valid = False
            try:
                ca_pub = _load_ca_public()
                sig = base64.b64decode(cert.get("signature", ""))
                ca_pub.verify(sig, cert.get("public_key_pem", "").encode("utf-8") + cert.get("identity", "").encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
                valid = True
            except Exception:
                valid = False
            certs.append({"path": str(p), "identity": cert.get("identity"), "valid": valid})
        except Exception:
            continue
    return certs


def get_certificate(identity: str):
    fn = _safe_filename(identity)
    p = USERS_DIR / f"{fn}.cert"
    if not p.exists():
        raise FileNotFoundError("Certificado de usuario no encontrado")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _decrypt_user_private_key(identity: str, password: str):
    fn = _safe_filename(identity)
    p = USERS_DIR / f"{fn}.key.enc"
    if not p.exists():
        raise FileNotFoundError("Clave privada del usuario no encontrada")

    data = p.read_bytes()
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    # Crear archivo temporal con nombre único y extensión .enc
    tmp_enc = Path(tempfile.gettempdir()) / f"userkey_dec_{secrets.token_hex(8)}.enc"
    tmp_out = Path(tempfile.gettempdir()) / f"userkey_dec_{secrets.token_hex(8)}.dec"

    try:
        # Escribir el ciphertext en el archivo temporal
        tmp_enc.write_bytes(ciphertext)
        
        key = _derive_key_from_password(password, salt)
        
        # Desencriptar usando el IV extraído
        AES_MODULE.desencriptar_archivo_AES(
            file_path=str(tmp_enc), 
            modeAES="CBC", 
            key=key, 
            iv=iv, 
            key_length_bits=256, 
            output_path=str(tmp_out)
        )

        # Cargar la clave privada desde el archivo descifrado
        priv = serialization.load_pem_private_key(tmp_out.read_bytes(), password=None, backend=default_backend())

        return priv
        
    except ValueError as e:
        # Si hay error de padding, podría ser contraseña incorrecta
        raise ValueError(f"No se pudo desencriptar: {e}. Verifica la contraseña.")
    except Exception as e:
        # Propagar el error original
        raise
    finally:
        # Limpiar archivos temporales siempre
        try:
            if tmp_enc.exists():
                tmp_enc.unlink()
        except Exception:
            pass
        try:
            if tmp_out.exists():
                tmp_out.unlink()
        except Exception:
            pass


def encrypt_for_recipients(input_file: str, recipients: list, algorithm: str, mode: str, output_file: str = None) -> str:
    """Cifra `input_file` para una lista de identities. Devuelve ruta al archivo cifrado híbrido."""
    if not recipients:
        raise ValueError("No recipients provided")
    # Determine key length
    key_bits = 256 if algorithm == "AES-256" else (192 if algorithm == "AES-192" else 128)
    key_bytes = key_bits // 8

    sym_key = secrets.token_bytes(key_bytes)

    # Use AES module to create ciphertext temporary file
    tmp_cipher_path = Path(tempfile.gettempdir()) / f"hybenc_{secrets.token_hex(8)}.enc"
    tmp_plain = Path(input_file)

    try:
        iv = AES_MODULE.encriptar_archivo_AES(
            file_path=input_file, 
            modeAES=mode, 
            key=sym_key, 
            key_length_bits=key_bits, 
            output_path=str(tmp_cipher_path)
        )

        ciphertext = tmp_cipher_path.read_bytes()

        # Encrypt sym_key for each recipient
        rec_list = []
        # ensure CA exists (this just loads public key, doesn't need private/license)
        _load_ca_public() 
        
        for identity in recipients:
            cert = get_certificate(identity)
            pub_pem = cert.get("public_key_pem").encode("utf-8")
            pub = serialization.load_pem_public_key(pub_pem, backend=default_backend())
            enc_sym = pub.encrypt(sym_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            rec_list.append({"identity": identity, "enc_key": base64.b64encode(enc_sym).decode("utf-8")})

        meta = {"algorithm": algorithm, "mode": mode, "iv": iv.hex(), "recipients": rec_list}
        meta_bytes = json.dumps(meta).encode("utf-8")

        if output_file is None:
            output_file = str(Path(input_file).with_suffix(Path(input_file).suffix + ".hybenc"))

        with open(output_file, "wb") as f:
            f.write(meta_bytes + SEPARATOR + ciphertext)

        return output_file
    finally:
        # cleanup temp
        try:
            if tmp_cipher_path.exists():
                tmp_cipher_path.unlink()
        except Exception:
            pass


def decrypt_hybrid_file(hybrid_file: str, identity: str, password: str, output_file: str = None) -> str:
    data = Path(hybrid_file).read_bytes()
    if SEPARATOR not in data:
        raise ValueError("Archivo no es híbrido o formato desconocido")

    meta_raw, ciphertext = data.split(SEPARATOR, 1)
    meta = json.loads(meta_raw.decode("utf-8"))
    algorithm = meta.get("algorithm")
    mode = meta.get("mode")
    iv = bytes.fromhex(meta.get("iv"))
    # Find recipient
    rec = None
    for r in meta.get("recipients", []):
        if r.get("identity") == identity:
            rec = r
            break
    if rec is None:
        raise PermissionError("Este usuario no es destinatario del archivo")

    enc_key = base64.b64decode(rec.get("enc_key"))

    # Decrypt user's private key
    user_priv = _decrypt_user_private_key(identity, password)
    sym_key = user_priv.decrypt(enc_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # Write ciphertext to temp .enc file and use AES module to decrypt
    tmp_enc = Path(tempfile.gettempdir()) / f"hybdec_{secrets.token_hex(8)}.enc"
    tmp_out = Path(tempfile.gettempdir()) / f"hybdec_{secrets.token_hex(8)}.dec"
    
    try:
        tmp_enc.write_bytes(ciphertext)
        
        key_bits = 256 if algorithm == "AES-256" else (192 if algorithm == "AES-192" else 128)
        AES_MODULE.desencriptar_archivo_AES(
            file_path=str(tmp_enc), 
            modeAES=mode, 
            key=sym_key, 
            iv=iv, 
            key_length_bits=key_bits, 
            output_path=str(tmp_out)
        )

        if output_file is None:
            output_file = str(tmp_out)
        else:
            # Move result to desired output
            tmp_out.rename(output_file)

        return output_file
    finally:
        try:
            if tmp_enc.exists():
                tmp_enc.unlink()
        except Exception:
            pass
        try:
            if tmp_out.exists():
                tmp_out.unlink()
        except Exception:
            pass