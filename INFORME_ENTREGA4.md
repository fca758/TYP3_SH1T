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

**INFORME ENTREGA 4 — APLICACIÓN DE ESCRITORIO PARA CIFRADO (E4)**

**Resumen ejecutivo**
- Proyecto: TYP3_SH1T — aplicación de escritorio que combina cifrado simétrico y asimétrico con una Autoridad Certificadora local para controlar el acceso a archivos mediante certificados básicos de usuario.
- Objetivos principales cubiertos:
  1. Generación de certificados básicos por usuario.
  2. Certificados firmados por la CA local (la propia aplicación).
  3. Almacenamiento seguro de la clave privada de la aplicación mediante un número de licencia (derivado por SHA-256 → clave AES).
  4. Selección de usuarios desde un listado para cifrar archivos/carpetas.
  5. Validación de certificados mediante la clave pública de la aplicación.
  6. Cifrado para múltiples destinatarios (hybrid encryption).
  7–9. Protección de claves privadas de usuarios con contraseña; solicitud de contraseña en recuperación; uso de la clave privada para recuperar datos.

**1. Introducción y conceptos**

1.1 Propósito
- Diseñar y proporcionar una herramienta de cifrado local con control de acceso por certificados, orientada a prácticas y evaluación: fácil de usar, con seguridad básica adecuada para un entorno académico/práctico.

1.2 Componentes principales y responsabilidades
- `certificacion.py`: gestión de CA, creación/listado/verificación de certificados, cifrado híbrido y recuperación de archivos.
- `typeShit_gui.py`: interfaz de usuario (crear CA, crear usuarios, seleccionar destinatarios, cifrar/descifrar).
- `aes.py`: módulo auxiliar que implementa AES (encriptar/desencriptar archivos). Debe proporcionar funciones: `encriptar_archivo_AES(...)` y `desencriptar_archivo_AES(...)`.

1.3 Algoritmos, protocolos y librerías
- Asimétrico: RSA 2048 bits — usos:
  - Firma de certificados por la CA: PKCS#1 v1.5 (firma con SHA-256).
  - Cifrado de clave simétrica: RSA-OAEP (MGF1(SHA-256), SHA-256) — para cifrar la clave AES usada por archivo.
- Simétrico: AES-256 CBC — usado para cifrar archivos y claves privadas en disco. Cada cifrado usa IV aleatorio distinto.
- Derivación de claves: PBKDF2-HMAC-SHA256 (100.000 iteraciones) — para derivar la clave AES que protege la clave privada de cada usuario a partir de su contraseña.
- Hash directo: SHA-256(license) — se usa como clave AES para cifrar la clave privada de la CA (diseñado por simplicidad para la práctica E4).
- Librería principal: `cryptography` (hazmat.primitives): RSA, padding, hashes, PBKDF2HMAC, serialization. GUI con `tkinter`.

1.4 Estructura de almacenamiento
- Carpeta `certs/` (creada por el módulo):
  - `certs/ca/ca_public.pem` — clave pública de la CA (PEM).
  - `certs/ca/ca_private.enc` — clave privada CA cifrada (iv||ciphertext), donde la key proviene de SHA-256(license).
  - `certs/license.txt` — número de licencia (texto plano) usado para derivar la clave de la CA. Sólo se escribe la primera vez.
  - `certs/users/<identity>.cert` — JSON con `identity`, `public_key_pem`, `signature`.
  - `certs/users/<identity>.key.enc` — privado cifrado (salt(16) || iv(16) || ciphertext).

**2. Funcionalidad — mapa de requisitos y su implementación**

2.1 Generación de certificados básicos para usuarios (Requisito 1)
- Implementado en `certificacion.create_user(identity, password)`. Genera par RSA, firma la clave pública con la clave privada de CA y guarda el certificado JSON.

2.2 Contenido del certificado y firma por la CA (Requisito 2)
- El certificado contiene la identidad, la clave pública (PEM) y la firma (base64) realizada por la CA sobre (public_key_pem || identity). La verificación se realiza con la clave pública de la CA. Ver: `certificacion.list_certificates()`.

2.3 Almacenamiento de la clave privada de la aplicación usando la licencia (Requisito 3)
- `certificacion.create_ca(license_number)` genera el par RSA para la CA, escribe la pública en `ca_public.pem` y cifra la privada con una key = SHA-256(license_number) usando AES-256 (CBC) a través del módulo `aes.py`. Se escribe `certs/license.txt` la primera vez.

2.4 Selección de usuario(s) desde un listado (Requisito 4 y 5)
- La GUI (`typeShit_gui.py`) lista certificados válidos (verificados con CA public) en el desplegable `Usuario activo` y en el diálogo de `Cifrado múltiple` (Listbox). Cuando se selecciona, el flujo obtiene el `public_key_pem` desde `certs/users/<id>.cert` y lo utiliza para cifrar la clave simétrica.

2.5 Cifrado para varios usuarios (Requisito 6)
- `certificacion.encrypt_for_recipients(input_file, recipients, algorithm, mode)` genera una `sym_key` AES, cifra el archivo con AES, y para cada destinatario cifra `sym_key` con RSA-OAEP usando la clave pública del destinatario. El archivo resultante `.hybenc` contiene metadatos JSON (algoritmo, mode, iv, recipients con enc_key) + SEPARATOR + ciphertext.

2.6 Protección de claves privadas de usuarios con contraseña (Requisito 7)
- La clave privada PEM se cifra con una clave derivada con PBKDF2 (salt de 16 bytes, 100000 iteraciones) y AES-256-CBC. Archivo: `salt || iv || ciphertext`.

2.7 Solicitud de contraseña para recuperar (Requisito 8)
- En el flujo de descifrado híbrido la GUI pide `identity` y `password` (diálogos simples); la contraseña se usa para descifrar `certs/users/<identity>.key.enc` mediante `_decrypt_user_private_key`.

2.8 Recuperación uso de la privada para recuperar el archivo (Requisito 9)
- Una vez descifrada la clave privada RSA, se usa para descifrar la `enc_key` (RSA-OAEP) para obtener la `sym_key`, y con esa clave se descifra el ciphertext AES para recuperar el fichero.

**3. Procedimiento práctico (práctica E4) — guión detallado paso a paso**

Objetivo de la práctica: demostrar en la app la creación de la CA y dos usuarios, cifrar un archivo para ambos y desencriptarlo por cada uno introduciendo su contraseña.

3.1 Preparación del entorno

Requisitos previos:
- Python 3.8+ (preferible 3.10+).
- Paquete `cryptography` instalado.
- Dependencia: Pillow (opcional, para la imagen de fondo en GUI).

Comandos (PowerShell):
```powershell
python -m pip install --user cryptography pillow
```

3.2 PASO A — Iniciar la aplicación GUI

1. Desde el directorio del proyecto ejecutar:
```powershell
python main.py
```
2. Abrir la ventana principal y comprobar que el desplegable `Usuario activo` está vacío si no hay certificados.

3.3 PASO B — Crear CA (única licencia)

1. Abrir `⚙ Gestionar certificados`.
2. En `Número de licencia` introducir, por ejemplo, `LIC-TEST-0001` y pulsar `Crear CA`.
   - La función `create_ca` generará la CA, guardará `certs/ca/ca_public.pem`, `certs/ca/ca_private.enc` y `certs/license.txt`.
3. El botón `Crear CA` quedará deshabilitado y el campo de licencia se desactivará.

Comandos equivalentes (si prefieres script/test):
```python
from certificacion import create_ca, get_license
create_ca('LIC-TEST-0001')
print('License stored:', get_license())
```

3.4 PASO C — Crear dos usuarios (alice, bob)

1. En `⚙ Gestionar certificados` -> `CREAR USUARIO` introducir:
   - Identidad: `alice`
   - Contraseña: `alicepw`
   - Pulsar `Crear usuario`.
2. Repetir para `bob` con contraseña `bobpw`.

Esto creará:
- `certs/users/alice.cert` (JSON con public_key_pem y signature).
- `certs/users/alice.key.enc` (salt||iv||ciphertext).

Script equivalente:
```python
from certificacion import create_user
create_user('alice', 'alicepw')
create_user('bob', 'bobpw')
```

3.5 PASO D — Preparar un fichero de prueba

1. Crear `prueba.txt` con contenido simple (por ejemplo, "Prueba E4: contenido secreto").

3.6 PASO E — Cifrar para múltiples destinatarios

1. En la ventana principal: seleccionar `Archivo entrada` → `prueba.txt`.
2. Pulsar `Cifrado múltiple` → seleccionar `alice` y `bob` → Confirmar.
3. Pulsar `Ejecutar` (acción `encrypt`) → se generará `prueba.txt.hybenc`.

Llamada programática equivalente:
```python
from certificacion import encrypt_for_recipients
out = encrypt_for_recipients('prueba.txt', ['alice','bob'], algorithm='AES-256', mode='CBC')
print('Out:', out)
```

3.7 PASO F — Recuperación por cada usuario

1. En la GUI elegir `Acción: decrypt` y abrir `prueba.txt.hybenc`.
2. Introducir `Identidad`: `alice` y `Contraseña`: `alicepw` cuando se solicite.
3. La aplicación descifrará: `_decrypt_user_private_key` recupera la clave privada de `alice`, se descifra su `enc_key` con RSA, se obtiene `sym_key` y finalmente se descifra el contenido con AES.
4. Repetir con `bob` y su contraseña.

Script de verificación:
```python
from certificacion import decrypt_hybrid_file
decrypt_hybrid_file('prueba.txt.hybenc', 'alice', 'alicepw', output_file='prueba_alice.txt')
decrypt_hybrid_file('prueba.txt.hybenc', 'bob', 'bobpw', output_file='prueba_bob.txt')
```

3.8 Casos de prueba y errores esperados

- Contraseña incorrecta -> `_decrypt_user_private_key` fallará al derivar la clave AES y la lectura PEM fallará: la app debe mostrar mensaje de error.
- Usuario no destinatario -> `decrypt_hybrid_file` lanzará PermissionError (no se encontró entrada de recipient).
- Certificado inválido (firma no válida) -> `list_certificates()` marcará certificado como inválido y no aparecerá en la lista de destinatarios válidos.

**4. Fragmentos de código explicativos**

4.1 Derivado de clave de licencia (CA)
```python
def _derive_key_from_license(license_number: str) -> bytes:
    return hashlib.sha256(license_number.encode('utf-8')).digest()
```

4.2 Cifrado de la clave privada de la CA (resumen):
```python
# cifrar archivo temporal con AES_MODULE.encriptar_archivo_AES
key = _derive_key_from_license(license_number)
iv = AES_MODULE.encriptar_archivo_AES(file_path=str(tf_path), modeAES='CBC', key=key, key_length_bits=256, output_path=str(tf_path)+'.enc')
# guardar iv + ciphertext en ca_private.enc
```

4.3 Protección de clave privada de usuario (PBKDF2 + AES)
```python
salt = secrets.token_bytes(16)
key = _derive_key_from_password(password, salt)  # PBKDF2HMAC
iv = AES_MODULE.encriptar_archivo_AES(file_path=str(tf_path), modeAES='CBC', key=key, key_length_bits=256, output_path=str(tf_path)+'.enc')
with open(user_key_path,'wb') as f:
    f.write(salt + iv + ciphertext)
```

4.4 Cifrado híbrido (por cada destinatario)
```python
sym_key = secrets.token_bytes(key_bytes)
iv = AES_MODULE.encriptar_archivo_AES(file_path=input_file, modeAES=mode, key=sym_key, key_length_bits=key_bits, output_path=str(tmp_cipher))
for identity in recipients:
    cert = get_certificate(identity)
    pub = serialization.load_pem_public_key(cert['public_key_pem'].encode('utf-8'))
    enc_sym = pub.encrypt(sym_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    rec_list.append({'identity':identity,'enc_key':base64.b64encode(enc_sym).decode('utf-8')})
```

4.5 Recuperación y uso de la clave privada del usuario
```python
user_priv = _decrypt_user_private_key(identity, password)
sym_key = user_priv.decrypt(enc_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
AES_MODULE.desencriptar_archivo_AES(file_path=str(tmp_enc), modeAES=mode, key=sym_key, iv=iv, key_length_bits=key_bits, output_path=str(tmp_out))
```

**5. Diagrama simplificado de mensajes (texto)**

Creación CA:
- GUI -> certificacion.create_ca(license) -> (genera par RSA) -> almacena `ca_public.pem`, cifra y guarda `ca_private.enc`, escribe `license.txt`.

Creación usuario:
- GUI -> certificacion.create_user(identity,password) -> (genera par RSA) -> firma con CA_priv -> guarda cert JSON + cifra privada.

Envío/cifrado a múltiples destinatarios:
- Usuario A -> GUI -> seleccionar destinatarios -> certificacion.encrypt_for_recipients -> output `.hybenc`.

Recuperación por destinatario:
- Destinatario -> GUI -> abrir `.hybenc` -> pedir identidad/contraseña -> certificacion.decrypt_hybrid_file -> devolver archivo plano.

**6. Manual de uso (conciso)**

6.1 Iniciar app
- `python main.py`

6.2 Gestionar certificados
- `⚙ Gestionar certificados` → Crear CA (si no existe), Crear usuarios, Eliminar usuarios.

6.3 Cifrar/Descifrar
- `Cifrado múltiple` para seleccionar varios destinatarios; `Ejecutar` para aplicar la acción (encrypt/decrypt).

**7. Bibliografía y librerías**

- cryptography — https://cryptography.io/en/latest/
- Documentación sobre AES (CBC), RSA-OAEP, PBKDF2-HMAC-SHA256, y buenas prácticas cripto.
- Recursos PKI y firmas digitales (material académico sobre X.509, aunque aquí se usa formato JSON simplificado).

**8. Conclusiones y recomendaciones**
- La práctica implementa de forma funcional los requisitos de E4: CA local, certificados firmados, cifrado híbrido múltiple, y protección de claves privadas por contraseña.
- Recomendaciones de mejora (post-práctica):
  - Reemplazar SHA-256(license) por KDF con salt para proteger la clave CA si la licencia pudiera ser débil.
  - Proteger el directorio `certs/` con permisos OS restringidos.
  - Añadir límites y mensajes más descriptivos en GUI para errores de contraseña y certificados inválidos.

**Apéndice A — Archivos relevantes en el repo**

- `certificacion.py` — lógica PKI y cifrado híbrido.
- `typeShit_gui.py` — GUI y flujo de usuario.
- `aes.py` — implementación AES usada por la app.
- `INFORME_ENTREGA4.md` — este documento.
- `TODO.txt` — lista de tareas pendientes y estado.

---

Documento generado y guardado en `INFORME_ENTREGA4.md`.

