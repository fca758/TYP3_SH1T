**Resumen**
- **Proyecto**: TYP3_SH1T — aplicación de escritorio para cifrado/descifrado con soporte de PKI local y cifrado híbrido.
- **Objetivos cubiertos**: implementación de una Autoridad Certificadora (CA) local, generación y gestión de certificados de usuario, cifrado híbrido para múltiples destinatarios, protección de claves privadas (CA y usuarios), UI integrada en `typeShit_gui.py`, y asegurar que existe un único número de licencia persistente (`certs/license.txt`).

**Introducción**
- **Propósito**: añadir firma digital y certificados para controlar acceso a archivos cifrados, permitir cifrado para múltiples destinatarios y garantizar que las claves privadas estén protegidas por contraseña.
- **Librerías principales**:
  - `cryptography` (hazmat.primitives): RSA, OAEP, PKCS1v15, hashes, PBKDF2HMAC, serialization.
  - Módulo local `aes.py`: funciones AES para cifrar/desencriptar archivos (interfaz utilizada para proteger claves y datos).
  - `tkinter`: interfaz gráfica (GUI).
- **Algoritmos y protocolos usados**:
  - Asimétrico: RSA-2048 para firmas y cifrado de claves (OAEP para cifrado de clave simétrica, PKCS1v15 para firma CA).
  - Simétrico: AES-256 en modo CBC (usado por `AES` del módulo `aes.py`) para cifrar archivos y para proteger claves privadas cuando procede.
  - Derivación de claves: PBKDF2-HMAC-SHA256 (100000 iteraciones) para derivar una AES key desde la contraseña del usuario.
  - Hashing: SHA-256 para derivar la clave de cifrado de la CA a partir del número de licencia (esta es la raíz de confianza en la app).
- **Relación entre componentes**:
  - La CA guarda su clave privada cifrada con una clave derivada del `license_number` (único para la instalación). La clave pública de la CA se usa para verificar firmas de certificados.
  - Cada usuario tiene un par RSA; la pública se guarda en `certs/users/<id>.cert` (JSON con firma CA), la privada en `certs/users/<id>.key.enc` cifrada con una clave derivada de su contraseña.
  - Para cifrar un archivo para múltiples destinatarios se genera una clave simétrica (AES) que cifra el archivo y se cifra esa clave con la clave pública RSA de cada destinatario. El fichero híbrido contiene metadatos (IV, algoritmo, recips) + ciphertext.

**Funcionalidad y solución a los requisitos (Entrega 4)**
**Objetivo: Un único número de licencia para toda la app**
- Implementación: `certificacion.create_ca(license_number)` genera la CA y escribe `certs/license.txt` con el número de licencia, y además se añadió `certificacion.get_license()` y `certificacion.has_ca()`.
- Medida de seguridad: Si ya existe `certs/license.txt` o una CA, la creación de una nueva CA está prohibida o debe usar la misma licencia. Esto evita cambios inadvertidos de la raíz de confianza.

**Objetivo: Cifrado múltiple (selección múltiple de destinatarios)**
- Interfaz: en `typeShit_gui.py` el botón `Cifrado múltiple` abre una ventana con `Listbox(selectmode=tk.MULTIPLE)` que permite seleccionar varios usuarios válidos.
- Lógica: `certificacion.encrypt_for_recipients(input_file, recipients, algorithm, mode)` genera una clave simétrica AES y cifra el fichero; para cada `recipient` lee su `public_key_pem` desde `certs/users/<id>.cert` y cifra la clave simétrica con RSA-OAEP, almacenando la lista de claves cifradas en los metadatos del fichero `.hybenc`.

**Objetivo: Cómo se guardan las claves de cada usuario**
- Publica (certificado): `certs/users/<identity>.cert` contiene JSON:
  - `identity`: cadena
  - `public_key_pem`: PEM de la clave pública
  - `signature`: firma CA sobre (public_key_pem || identity)
- Privada (protegida): `certs/users/<identity>.key.enc` es binario con estructura `salt(16) || iv(16) || ciphertext`. El `salt` se usa en PBKDF2 para derivar una key AES-256 desde la contraseña del usuario, y `iv` + `ciphertext` es el resultado de `AES_MODULE.encriptar_archivo_AES` aplicado a la representación PEM de la clave privada.

**Requisitos 7, 8 y 9 (protección y recuperación de claves privadas)**
- (7) Protegidas por contraseña: `create_user()` genera `salt = secrets.token_bytes(16)` y usa `_derive_key_from_password(password, salt)` (PBKDF2HMAC-SHA256, 100000 iteraciones) para derivar la key que cifra la privada.
- (8) Solicitud de contraseña: Al desencriptar un `.hybenc`, la GUI solicita la `identity` y `password` (ventana de diálogo). La función `certificacion.decrypt_hybrid_file(hybrid_file, identity, password)` invoca `_decrypt_user_private_key(identity, password)`.
- (9) Recuperación y uso: `_decrypt_user_private_key` descifra el fichero `key.enc` escribiendo un temporal descifrado y carga la clave RSA privada; esa clave se usa para descifrar la `enc_key` (RSA-OAEP) y con la clave simétrica resultante se desencripta el archivo (AES MODULE).

**Diagrama de alto nivel (flujos)**
- CA creación
```
User (gestor) -> GUI (Crear CA) -> certificacion.create_ca(license)
  -> genera RSA CA
  -> guarda ca_public.pem
  -> cifra ca_private.pem con key = SHA256(license) (AES-256 CBC)
  -> escribe certs/license.txt
```

- Crear usuario
```
User (gestor) -> GUI (Crear usuario: identity, password)
  -> certificacion.create_user(identity, password)
  -> genera par RSA usuario
  -> firma: signature = CA_priv.sign(pub_pem || identity)
  -> guarda cert JSON en certs/users/<id>.cert
  -> cifra private PEM con key = PBKDF2(password, salt) -> guarda en certs/users/<id>.key.enc
```

- Cifrado híbrido (para N destinatarios)
```
Sender -> GUI (Cifrar + seleccionar destinatarios) -> certificacion.encrypt_for_recipients(file, [A,B,...])
  -> genera sym_key (AES)
  -> cifra file con AES(sym_key) -> ciphertext
  -> por cada recipient: carga public_key, enc_sym = RSA(pub).encrypt(sym_key, OAEP)
  -> meta = {algorithm, mode, iv, recipients: [{identity, enc_key}, ...]}
  -> output file = meta || SEPARATOR || ciphertext  (.hybenc)
```

- Desencriptado por recipient
```
Recipient -> GUI (Abrir .hybenc) -> Introduce identity + password -> certificacion.decrypt_hybrid_file(hyb, identity, password)
  -> parse meta, find recipient entry (enc_key)
  -> _decrypt_user_private_key(identity, password) -> load RSA private
  -> sym_key = RSA(private).decrypt(enc_key, OAEP)
  -> AES decrypt ciphertext with sym_key + iv -> produce plaintext
```

**Manual de usuario (resumido)**
- Preparación inicial:
  1. Ejecuta la aplicación principal `python main.py` (o arranca el ejecutable de la GUI).
  2. Abre `⚙ Gestionar certificados` (parte superior).
  3. Si no existe una CA, introduce el **número de licencia** y pulsa `Crear CA`. El número de licencia se guarda en `certs/license.txt` y NO podrá cambiarse desde la app.
- Crear usuarios:
  1. Desde `⚙ Gestionar certificados` en la sección `CREAR USUARIO`, introduce `Identidad` y `Contraseña` y pulsa `Crear usuario`.
  2. La identidad quedará disponible en la lista de certificados y en el desplegable `Usuario activo` de la ventana principal.
- Cifrar archivo para múltiples destinatarios:
  1. En la ventana principal selecciona `Acción: encrypt`.
  2. Selecciona `Archivo entrada`, `Algoritmo`, `Modo` y una clave (si usas cifrado simétrico directo). Para cifrado múltiple pulsa `Cifrado múltiple`.
  3. Selecciona los destinatarios (múltiple selección) y confirma. Aparecerá en la salida que la configuración está activa.
  4. Haz `Ejecutar` para generar un archivo `.hybenc`.
- Desencriptar `.hybenc`:
  1. Selecciona `Acción: decrypt` y abre el `.hybenc` como `Archivo entrada`.
  2. Si el archivo es híbrido la GUI pedirá `Identidad` y `Contraseña`.
  3. Tras introducir la contraseña válida, el archivo se descifra y se guarda en disco (ruta devuelta por la función de descifrado).
- Eliminar usuarios:
  - Desde `⚙ Gestionar certificados` selecciona el usuario en la lista y pulsa `🗑 Eliminar usuario`. Esto eliminará `certs/users/<id>.cert` y `certs/users/<id>.key.enc`.

**Fragmentos de código (porciones relevantes)**
- Derivar clave de license (SHA-256):
```
# certificacion.py
def _derive_key_from_license(license_number: str) -> bytes:
    return hashlib.sha256(license_number.encode("utf-8")).digest()
```

- Crear CA (puntos críticos): (resumen)
```
private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
pub_pem = public_key.public_bytes(...)
# escribir ca_public.pem
# serializar private a temp y cifrar con AES usando key = SHA256(license)
iv = AES_MODULE.encriptar_archivo_AES(file_path=str(tf_path), modeAES="CBC", key=key, key_length_bits=256, output_path=...) 
# guardar priv_path = iv || ciphertext
# escribir certs/license.txt si no existe
```

- Crear usuario y proteger privada con contraseña:
```
# generar par RSA
pub_pem = public_key.public_bytes(...)
# firmar con CA private
ca_priv = _load_ca_private(license_number)
signature = ca_priv.sign(pub_pem + identity_bytes, padding.PKCS1v15(), hashes.SHA256())
# guardar JSON con public_key_pem y signature
# cifrar private:
salt = secrets.token_bytes(16)
key = _derive_key_from_password(password, salt)  # PBKDF2HMAC
iv = AES_MODULE.encriptar_archivo_AES(file_path=str(tf_path), modeAES="CBC", key=key, key_length_bits=256, output_path=...)
# guardar: salt || iv || ciphertext
```

- Cifrado híbrido (clave simétrica cifrada por RSA-OAEP por cada destinatario):
```
sym_key = secrets.token_bytes(key_bytes)
iv = AES_MODULE.encriptar_archivo_AES(file_path=input_file, modeAES=mode, key=sym_key, key_length_bits=key_bits, output_path=tmp_cipher)
for identity in recipients:
    cert = get_certificate(identity)
    pub = serialization.load_pem_public_key(cert["public_key_pem"].encode("utf-8"))
    enc_sym = pub.encrypt(sym_key, padding.OAEP(...))
    rec_list.append({"identity": identity, "enc_key": base64.b64encode(enc_sym).decode("utf-8")})
# escribir meta + SEPARATOR + ciphertext
```

- Recuperación de clave privada y uso para descifrar:
```
# decrypt_hybrid_file
rec = find_recipient(meta, identity)
enc_key = base64.b64decode(rec['enc_key'])
user_priv = _decrypt_user_private_key(identity, password)  # usa salt, PBKDF2
sym_key = user_priv.decrypt(enc_key, padding.OAEP(...))
AES_MODULE.desencriptar_archivo_AES(temp_enc, modeAES=mode, key=sym_key, iv=iv, output=out)
```

**Consideraciones de seguridad**
- El diseño separa claramente: la CA se protege con la `license` y las claves de usuario con contraseñas individuales (PBKDF2 + salt). Esto sigue buenas prácticas básicas.
- Riesgos y limitaciones:
  - El derivado de la clave de la CA usando SHA-256(license) es simple; si la licencia es débil, la protección de la CA quedará comprometida. Recomendación: usar una licencia suficientemente larga/aleatoria o mejorar a KDF+salt si se desea mayor robustez.
  - La gestión del `certs/` en el sistema de archivos confía en permisos OS; si un adversario tiene acceso al disco, puede intentar ataques offline (por ejemplo, fuerza bruta de contraseñas). Recomendación: proteger `certs/` con permisos restrictivos.
  - El módulo AES usado (`aes.py`) debe implementarse correctamente y no reusar IVs. Se usa IV por archivo y se almacena en metadatos.

**Bibliografía y librerías**
- `cryptography` (https://cryptography.io) — RSA, OAEP, PKCS1v15, PBKDF2HMAC, serialization.
- Documentación AES / CBC y necesidades de IV y padding.
- Documentos sobre PKI y firmas (X.509 no usado; certificación local en JSON simplificada).

**Dónde están los ficheros clave en el repo**
- `certificacion.py` — implementación PKI, CA, user mgmt, cifrado híbrido.
- `typeShit_gui.py` — GUI integrada: gestión de certificados, selección múltiple, cifrar/descifrar.
- `aes.py` — funciones AES para cifrar/desencriptar archivos.
- `TODO.txt` — lista de tareas y notas de progreso.
- `certs/` — carpeta donde se crean: `ca/ca_public.pem`, `ca/ca_private.enc`, `license.txt`, `users/<user>.cert`, `users/<user>.key.enc`.

**Pruebas recomendadas (pasos rápidos E2E)**
1. Ejecutar la app y crear CA con `license='LIC-TEST-0001'`.
2. Crear dos usuarios: `alice` (pw: `alicepw`), `bob` (pw: `bobpw`).
3. Preparar un fichero de texto `prueba.txt` con contenido.
4. En UI: seleccionar `Cifrado múltiple`, seleccionar `alice` y `bob`, ejecutar cifrado → generar `prueba.txt.hybenc`.
5. En UI: desencriptar `prueba.txt.hybenc` introduciendo `alice` y `alicepw`, verificar que el contenido coincide.
6. Repetir con `bob` y su contraseña.

Si quieres, puedo ejecutar automáticamente este flujo de prueba en el entorno (crear CA/usuarios y cifrar/descifrar un archivo pequeño). Confírmame si autorizas crear archivos en `certs/` y en el repo (por ejemplo usar identidades: `test_alice/test_bob` con contraseñas que elijas o que yo genere aleatorias). 

----

**Fin del informe**

Archivo creado: `INFORME_ENTREGA4.md` en la raíz del proyecto.

