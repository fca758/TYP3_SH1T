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

from aes import AES

AES_MODULE = AES()

ROOT = Path("certs")
USERS_DIR = ROOT / "users"
CA_DIR = ROOT / "ca"

SEPARATOR = b"\n---CERTMETA-END---\n"

def _ensure_dirs():
    for d in (ROOT, USERS_DIR, CA_DIR):
        if not d.exists():
            d.mkdir(parents=True)

def _safe_filename(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()

def _derive_key_from_license(license_number: str) -> bytes:
    # Simple derivation as requested: SHA-256 hash of license
    return hashlib.sha256(license_number.encode("utf-8")).digest()

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    # PBKDF2 with reasonable iterations
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend())
    return kdf.derive(password.encode("utf-8"))


def create_ca(license_number: str, key_size: int = 2048) -> None:
    """Genera clave RSA de la autoridad (CA) y guarda la pública y la privada cifrada por licencia."""
    _ensure_dirs()
    priv_path = CA_DIR / "ca_private.enc"
    pub_path = CA_DIR / "ca_public.pem"

    # Generate RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    # Serialize public
    pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    # Serialize private to temp file
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        tf_path = Path(tf.name)

    # Encrypt private using AES-256 with key derived from license (no salt per spec)
    key = _derive_key_from_license(license_number)
    iv = AES_MODULE.encriptar_archivo_AES(file_path=str(tf_path), modeAES="CBC", key=key, key_length_bits=256, output_path=str(tf_path) + ".enc")

    # Read ciphertext and write final file as iv||ciphertext
    ciphertext = Path(str(tf_path) + ".enc").read_bytes()
    with open(priv_path, "wb") as f:
        f.write(iv + ciphertext)

    # Cleanup temps
    try:
        tf_path.unlink()
    except Exception:
        pass
    try:
        Path(str(tf_path) + ".enc").unlink()
    except Exception:
        pass


def _load_ca_public() -> serialization.PublicFormat:
    pub_path = CA_DIR / "ca_public.pem"
    if not pub_path.exists():
        raise FileNotFoundError("CA public key not found. Create CA first.")
    return serialization.load_pem_public_key(pub_path.read_bytes(), backend=default_backend())


def _load_ca_private(license_number: str):
    priv_path = CA_DIR / "ca_private.enc"
    if not priv_path.exists():
        raise FileNotFoundError("CA private key not found. Create CA first.")

    data = priv_path.read_bytes()
    iv = data[:16]
    ciphertext = data[16:]

    # write ciphertext to temp .enc file for AES module
    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tf:
        tf.write(ciphertext)
        tmp_enc = Path(tf.name)

    key = _derive_key_from_license(license_number)
    # Decrypt to temp plaintext
    tmp_out = Path(str(tmp_enc) + ".dec")
    AES_MODULE.desencriptar_archivo_AES(file_path=str(tmp_enc), modeAES="CBC", key=key, iv=iv, key_length_bits=256, output_path=str(tmp_out))

    priv = serialization.load_pem_private_key(tmp_out.read_bytes(), password=None, backend=default_backend())

    # Cleanup
    try:
        tmp_enc.unlink()
        tmp_out.unlink()
    except Exception:
        pass

    return priv


def create_user(identity: str, password: str, license_number: str, key_size: int = 2048) -> None:
    """Genera par RSA para usuario, crea certificado firmado por CA y guarda clave privada cifrada por contraseña."""
    _ensure_dirs()
    fn = _safe_filename(identity)
    user_cert_path = USERS_DIR / f"{fn}.cert"
    user_key_path = USERS_DIR / f"{fn}.key.enc"

    # Generate user key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    ident_bytes = identity.encode("utf-8")

    # Sign with CA private
    ca_priv = _load_ca_private(license_number)
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

    # write private to temp file
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        tf_path = Path(tf.name)

    iv = AES_MODULE.encriptar_archivo_AES(file_path=str(tf_path), modeAES="CBC", key=key, key_length_bits=256, output_path=str(tf_path) + ".enc")

    ciphertext = Path(str(tf_path) + ".enc").read_bytes()

    # Final file structure: salt(16) || iv(16) || ciphertext
    with open(user_key_path, "wb") as f:
        f.write(salt + iv + ciphertext)

    # cleanup temps
    try:
        tf_path.unlink()
        Path(str(tf_path) + ".enc").unlink()
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

    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tf:
        tf.write(ciphertext)
        tmp_enc = Path(tf.name)

    key = _derive_key_from_password(password, salt)
    tmp_out = Path(str(tmp_enc) + ".dec")
    AES_MODULE.desencriptar_archivo_AES(file_path=str(tmp_enc), modeAES="CBC", key=key, iv=iv, key_length_bits=256, output_path=str(tmp_out))

    priv = serialization.load_pem_private_key(tmp_out.read_bytes(), password=None, backend=default_backend())

    try:
        tmp_enc.unlink()
        tmp_out.unlink()
    except Exception:
        pass

    return priv


def encrypt_for_recipients(input_file: str, recipients: list, algorithm: str, mode: str, output_file: str = None) -> str:
    """Cifra `input_file` para una lista de identities. Devuelve ruta al archivo cifrado híbrido."""
    if not recipients:
        raise ValueError("No recipients provided")
    # Determine key length
    key_bits = 256 if algorithm == "AES-256" else (192 if algorithm == "AES-192" else 128)
    key_bytes = key_bits // 8

    sym_key = secrets.token_bytes(key_bytes)

    # Use AES module to create ciphertext temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tf:
        tmp_cipher_path = Path(tf.name)

    iv = AES_MODULE.encriptar_archivo_AES(file_path=input_file, modeAES=mode, key=sym_key, key_length_bits=key_bits, output_path=str(tmp_cipher_path))

    ciphertext = tmp_cipher_path.read_bytes()

    # Encrypt sym_key for each recipient
    rec_list = []
    ca_pub = _load_ca_public()  # ensure CA exists
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

    # cleanup temp
    try:
        tmp_cipher_path.unlink()
    except Exception:
        pass

    return output_file


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
    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tf:
        tf.write(ciphertext)
        tmp_enc = Path(tf.name)

    key_bits = 256 if algorithm == "AES-256" else (192 if algorithm == "AES-192" else 128)
    tmp_out = Path(str(tmp_enc) + ".dec")
    AES_MODULE.desencriptar_archivo_AES(file_path=str(tmp_enc), modeAES=mode, key=sym_key, iv=iv, key_length_bits=key_bits, output_path=str(tmp_out))

    if output_file is None:
        output_file = str(tmp_out)

    # Move result to desired output
    Path(str(tmp_out)).rename(output_file)

    try:
        tmp_enc.unlink()
    except Exception:
        pass

    return output_file
