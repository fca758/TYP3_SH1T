# Informe Técnico de Criptografía

Este documento detalla todos los métodos criptográficos implementados en el proyecto, clasificándolos por su naturaleza y uso. Se incluyen extractos de código relevantes para facilitar la auditoría y comprensión del sistema.

---

## 1. Cifrado Simétrico (AES)

El núcleo del cifrado de archivos se basa en el estándar **AES (Advanced Encryption Standard)**. Este módulo se encarga de cifrar directamente el contenido de los archivos.

*   **Archivo Principal:** `aes.py`
*   **Librería:** `cryptography.hazmat.primitives.ciphers` (OpenSSL backend)
*   **Modos Soportados:** CBC, CFB, OFB
*   **Padding:** PKCS7 (128 bits)

### Código Clave: Cifrado de Archivos

```python
# aes.py

def encriptar_archivo_AES(self, file_path: str, modeAES: str, key: bytes, key_length_bits: int, output_path: str = None) -> bytes:
    # ...
    # 1. Configuración del Cifrador (Cipher)
    cipher = Cipher(algorithms.AES(key), modeCipher, backend=backend)
    encryptor = cipher.encryptor()

    # 2. Padding PKCS7 (Bloques de 128 bits)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # 3. Cifrado efectivo
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # ...
```

---

## 2. Cifrado Asimétrico (RSA) & Gestión de Certificados

El sistema implementa una infraestructura de clave pública (PKI) simplificada, con una Autoridad de Certificación (CA) interna que firma los certificados de los usuarios.

*   **Archivo Principal:** `certificacion.py`
*   **Algoritmo:** RSA
*   **Tamaño de Clave:** Configurable (Default: 2048 bits)
*   **Exponente Público:** 65537
*   **Firma:** SHA-256 con Padding PKCS1v15

### Código Clave: Generación de Usuarios y Firma

```python
# certificacion.py

def create_user(identity: str, password: str, key_size: int = 2048) -> None:
    # 1. Generar par de claves RSA
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    
    # 2. Firmar la clave pública con la CA (SHA-256)
    signature = ca_priv.sign(
        pub_pem + ident_bytes, 
        padding.PKCS1v15(), 
        hashes.SHA256()
    )
```

---

## 3. Cifrado Híbrido (Multi-Destinatario)

Para compartir archivos de forma segura entre usuarios, se utiliza un esquema híbrido: el archivo se cifra con AES (rápido) y la clave AES se cifra con RSA (seguro) para cada destinatario.

*   **Archivo Principal:** `certificacion.py`
*   **Esquema:** AES-256 (Datos) + RSA-OAEP (Intercambio de Clave)
*   **Hashing:** SHA-256 (usado dentro de OAEP)

### Código Clave: Encapsulamiento de Clave (KEM)

```python
# certificacion.py - función encrypt_for_recipients

# 1. Cifrar archivo con AES (genera iv y ciphertext)
iv = AES_MODULE.encriptar_archivo_AES(..., key=sym_key, ...)

# 2. Cifrar la clave AES (sym_key) para cada destinatario usando su RSA Public Key
enc_sym = pub.encrypt(
    sym_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), # Mask Generation Function
        algorithm=hashes.SHA256(),                   # Hash Algorithm
        label=None
    )
)
```

---

## 4. Protección y Derivación de Claves

El sistema emplea mecanismos robustos para proteger las claves privadas y los almacenes de claves en disco, evitando que se guarden en texto plano.

*   **Archivos:** `certificacion.py` y `user_keys.py`
*   **Algoritmos:** PBKDF2HMAC, SHA-256 (Hashing directo)

### Código Clave: Derivación de Contraseña (PBKDF2)

Para proteger la clave privada RSA del usuario con su contraseña:

```python
# certificacion.py

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000, # 100k iteraciones para resistencia a fuerza bruta
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))
```

### Código Clave: Derivación de Clave de Almacén (SHA-256)

Para proteger el archivo de claves AES (`_keys.enc`) usando la identidad del usuario (su clave privada), sin pedir la contraseña de nuevo:

```python
# user_keys.py

# Transforma la Clave Privada RSA (arbitrariamente larga) en una Clave AES (32 bytes fijos)
key_material = user_priv.private_bytes(...)
aes_key = hashlib.sha256(key_material).digest()
```
