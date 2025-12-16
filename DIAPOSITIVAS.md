# CONTENIDO VISUAL - DIAPOSITIVAS DE PRESENTACIÓN

---

## 🔹 Diapositiva 1: Portada

**Título Principal:**
Sistema de Cifrado Híbrido y Gestión de Certificados

**Subtítulo:**
Implementación de Infraestructura de Clave Pública (PKI) y Cifrado AES

**Datos:**
*   **Autor:** [Tu Nombre]
*   **Asignatura:** Teoría de Códigos y Criptografía
*   **Fecha:** Diciembre 2025

---

## 🔹 Diapositiva 2: Resumen del Proyecto

**Objetivo Principal:**
Desarrollar una aplicación segura para el cifrado y descifrado de archivos entre múltiples usuarios autenticados.

**Hitos Alcanzados (100%):**
✅ **Infraestructura PKI:** Simulación de Autoridad de Certificación (CA).
✅ **Gestión de Identidades:** Certificados digitales y claves privadas protegidas.
✅ **Cifrado Híbrido:** Combinación eficiente de AES-256 y RSA-2048.
✅ **Seguridad Robusta:** Protección de claves mediante PBKDF2 y cifrado AES.
✅ **Recuperación:** Acceso garantizado a archivos propios mediante auto-inclusión.

---

## 🔹 Diapositiva 3: Introducción Técnica

**Tecnologías Base:**
*   **Lenguaje:** Python 3.11
*   **Librería Criptográfica:** `cryptography.io` (Estándar industrial)
*   **Interfaz:** Tkinter

**Algoritmos Utilizados:**

| Tipo | Algoritmo | Configuración | Uso |
| :--- | :--- | :--- | :--- |
| **Simétrico** | **AES-CBC** | 256 bits + IV Aleatorio | Cifrado de archivos y claves privadas |
| **Asimétrico** | **RSA** | 2048 bits | Intercambio de claves y Firmas |
| **Hash/KDF** | **SHA-256** | PBKDF2 (100k iter.) | Derivación de claves y firmas |

---

## 🔹 Diapositiva 4: Arquitectura de Seguridad

**Gestión de Claves Privadas:**
1.  **Entrada:** Contraseña del Usuario.
2.  **Derivación:** `PBKDF2-HMAC-SHA256` + Salt (16 bytes).
3.  **Almacenamiento:** Archivo cifrado en disco (`.key.enc`).

**Estructura de Archivo Cifrado (.hybenc):**
*   **Cabecera JSON:**
    *   Algoritmo y Modo (AES-256-CBC).
    *   IV (Vector de Inicialización).
    *   Lista de Destinatarios (Identidad + Clave de Sesión cifrada con RSA).
*   **Cuerpo Binario:**
    *   Datos del archivo cifrados.

---

## 🔹 Diapositiva 5: Protocolo de Cifrado Híbrido

**Flujo de Proceso:**

1.  **Generación de Clave de Sesión:**
    *   Se crea una clave aleatoria AES de 32 bytes (256 bits).

2.  **Cifrado del Documento:**
    *   El archivo original se cifra UNA vez usando la Clave de Sesión.

3.  **Encapsulamiento de Claves:**
    *   Para cada destinatario (Alice, Bob, etc.):
        *   Se obtiene su **Clave Pública** del certificado.
        *   Se cifra la Clave de Sesión usando **RSA-OAEP**.

4.  **Empaquetado:**
    *   Se unen los metadatos y el cifrado en un solo archivo `.hybenc`.

**(Espacio para Diagrama de Flujo)**

---

## 🔹 Diapositiva 6: Protocolo de Descifrado

**Flujo de Proceso:**

1.  **Autenticación:**
    *   Usuario introduce contraseña -> Se desbloquea su Clave Privada RSA.

2.  **Recuperación de Clave:**
    *   El sistema busca la entrada del usuario en la cabecera del archivo.
    *   Descifra la Clave de Sesión usando su Clave Privada.

3.  **Descifrado del Documento:**
    *   Usa la Clave de Sesión recuperada para descifrar el cuerpo del archivo AES.

**(Espacio para Diagrama Inverso)**

---

## 🔹 Diapositiva 7: Funcionalidad y Manual de Usuario

**Acciones Disponibles:**

1.  **🔐 Gestión de Certificados:**
    *   Crear nuevos usuarios (Generación de par de claves).
    *   Verificar estado de certificados (Validación de firma CA).

2.  **📂 Cifrado Múltiple:**
    *   Selección visual de destinatarios.
    *   **Auto-inclusión:** El remitente siempre se incluye automáticamente.

3.  **🔑 Gestión de Claves:**
    *   Almacenamiento automático y seguro de claves utilizadas.
    *   Búsqueda de claves protegida por contraseña.

---

## 🔹 Diapositiva 8: Implementación - Cifrado Asimétrico

**Firma Digital (Integridad):**
```python
signature = ca_priv.sign(
    data=public_key_bytes + identity_bytes,
    padding=padding.PKCS1v15(),
    algorithm=hashes.SHA256()
)
```

**Intercambio de Claves (Confidencialidad):**
```python
encrypted_key = public_key.encrypt(
    session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

---

## 🔹 Diapositiva 9: Implementación - Protección de Claves

**Derivación de Clave Robusta (PBKDF2):**

```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=100000,  # Alta resistencia a fuerza bruta
    backend=default_backend()
)
user_aes_key = kdf.derive(password.encode())
```

*Clave utilizada para cifrar el almacenamiento local de la clave privada.*

---

## 🔹 Diapositiva 10: Conclusiones

**Resumen de Logros:**
*   Sistema completo y funcional de cifrado híbrido.
*   Cumplimiento total de requisitos de seguridad y usabilidad.
*   Implementación de estándares criptográficos modernos.

**Recursos y Bibliografía:**
*   Documentación oficial `cryptography.io`
*   Estándares NIST (AES, RSA)
*   RFC 8018 (PKCS #5: PBKDF2)

**¿Preguntas?**
