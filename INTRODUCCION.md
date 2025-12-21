# Introducción al Proyecto TYP3_$HIT
## Sistema Integral de Criptografía para Cifrado Seguro de Archivos

---

## Presentación

El proyecto **TYP3_$HIT** constituye una aplicación completa de criptografía aplicada que integra tres pilares fundamentales de la seguridad informática moderna: **cifrado simétrico**, **cifrado asimétrico** y **certificación digital mediante firmas**. Este sistema permite a múltiples usuarios cifrar, descifrar y compartir archivos de forma segura, implementando una infraestructura de clave pública (PKI) completamente funcional.

---

## Contexto y Motivación

En la era digital actual, la protección de la información confidencial es esencial. Ya sea para:
- Compartir documentos empresariales sensibles
- Proteger información personal contra accesos no autorizados
- Garantizar la autenticidad de archivos recibidos
- Cumplir con normativas de protección de datos (GDPR, LOPD)

Se requieren sistemas robustos que combinen **confidencialidad**, **integridad** y **autenticación**. Este proyecto implementa dichos principios mediante técnicas criptográficas estándar de la industria.

---

## Objetivos del Proyecto

### Objetivo Principal
Desarrollar una aplicación de escritorio que permita el cifrado y descifrado seguro de archivos entre múltiples usuarios autenticados, utilizando algoritmos criptográficos de estándar industrial.

### Objetivos Específicos

1. **Implementar Cifrado Simétrico (AES)**
   - Algoritmo AES en sus tres variantes: 128, 192 y 256 bits
   - Tres modos de operación: CBC, CFB y OFB
   - Generación automática de vectores de inicialización (IV)
   - Padding PKCS7 para bloques completos

2. **Implementar Cifrado Asimétrico (RSA)**
   - Generación de pares de claves RSA de 2048 bits
   - Cifrado de claves simétricas con RSA-OAEP
   - Protección de claves privadas mediante derivación PBKDF2

3. **Desarrollar Sistema de Certificación Digital**
   - Autoridad de Certificación (CA) simulada
   - Generación y firma de certificados de usuario
   - Verificación de autenticidad mediante firmas RSA + SHA-256
   - Sistema de cifrado híbrido para múltiples destinatarios

4. **Crear Interfaz de Usuario Intuitiva**
   - GUI con Tkinter para facilitar el uso
   - Gestión visual de certificados y destinatarios
   - Almacenamiento automático y seguro de claves utilizadas

---

## Entregas Integradas

Este documento recopila las tres entregas principales del proyecto:

### 📦 Entrega 1: Cifrado Simétrico con AES
- **Archivo:** `aes.py`
- **Funcionalidad:** Implementación del algoritmo AES en múltiples configuraciones
- **Características:**
  - Soporte para claves de 128, 192 y 256 bits
  - Modos CBC, CFB y OFB con IV aleatorio
  - Validación estricta de parámetros
  - Gestión segura de memoria

### 📦 Entrega 2: Cifrado Asimétrico con RSA
- **Archivo:** `rsa.py`
- **Funcionalidad:** Cifrado y descifrado con claves públicas/privadas
- **Características:**
  - Claves RSA de 2048 bits
  - Padding OAEP (más seguro que PKCS1v15)
  - Compatibilidad con formato PEM
  - Diseñado para cifrar claves AES (tamaño pequeño)

### 📦 Entrega 3: Infraestructura PKI y Certificación Digital
- **Archivo:** `certificacion.py`
- **Funcionalidad:** Sistema completo de gestión de identidades y cifrado híbrido
- **Características:**
  - Autoridad de Certificación con firma digital
  - Certificados de usuario verificables
  - Cifrado híbrido (AES + RSA) para múltiples destinatarios
  - Protección de claves privadas con PBKDF2 (100,000 iteraciones)
  - Control de acceso basado en identidad

---

## Arquitectura del Sistema

El sistema está organizado en capas modulares:

```
┌─────────────────────────────────────────┐
│     Capa de Presentación (GUI)          │
│         typeShit_gui.py                 │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│    Capa de Lógica de Negocio            │
│ typeShit.py (Gestión de operaciones)    │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│  Capa de Certificación y PKI            │
│       certificacion.py                  │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│   Capa de Primitivas Criptográficas     │
│        aes.py + rsa.py                  │
└─────────────────────────────────────────┘
```

---

## Algoritmos y Tecnologías Utilizadas

### Algoritmos Criptográficos

| Tipo           | Algoritmo   | Configuración      | Uso Principal         |
| :------------- | :---------- | :----------------- | :-------------------- |
| **Simétrico**  | AES         | 256 bits, modo CBC | Cifrado de archivos   |
| **Asimétrico** | RSA         | 2048 bits, OAEP    | Intercambio de claves |
| **Hash**       | SHA-256     | -                  | Firmas digitales      |
| **KDF**        | PBKDF2-HMAC | 100k iteraciones   | Derivación de claves  |

### Stack Tecnológico

- **Lenguaje:** Python 3.11+
- **Librería Criptográfica:** `cryptography.io` (Estándar de la industria)
- **Interfaz Gráfica:** Tkinter (Built-in Python)
- **Formato de Datos:** JSON para metadatos, binario para ciphertext
- **Gestión de Aleatoriedad:** `secrets` module (CSPRNG)

---

## Funcionamiento del Sistema

### Cifrado Híbrido: Cómo Funciona

El sistema implementa **cifrado híbrido**, combinando las ventajas de AES (velocidad) y RSA (seguridad en intercambio de claves):

#### Flujo de Cifrado
1. **Alice** quiere enviar un archivo a **Bob** y **Charlie**
2. El sistema genera una **clave AES aleatoria** (clave de sesión)
3. Cifra el archivo completo con **AES-256-CBC**
4. Para cada destinatario:
   - Obtiene su certificado digital
   - Extrae su **clave pública RSA**
   - Cifra la clave de sesión con **RSA-OAEP**
5. Empaqueta todo en un archivo `.hybenc`:
   - **Cabecera JSON:** Metadatos + claves cifradas para cada destinatario
   - **Cuerpo Binario:** Archivo cifrado con AES

#### Flujo de Descifrado
1. **Bob** abre el archivo `.hybenc`
2. El sistema lee la cabecera y verifica que Bob está autorizado
3. Bob introduce su **contraseña**
4. El sistema:
   - Descifra la clave privada RSA de Bob (protegida con PBKDF2)
   - Usa la clave privada para descifrar la clave de sesión AES
   - Descifra el archivo con la clave de sesión
5. Bob recupera el archivo original

**Ventaja clave:** El archivo se cifra **una sola vez** con AES (rápido), pero cada destinatario puede descifrarlo de forma independiente con su propia clave privada.

---

## Pilares de Seguridad

### 1. Confidencialidad
- **AES-256:** Algoritmo de cifrado simétrico aprobado por la NSA para información clasificada
- **RSA-2048:** Intercambio seguro de claves, equivalente a ~112 bits de seguridad
- **IV Aleatorio:** Cada cifrado usa un vector de inicialización único (previene ataques de patrón)

### 2. Integridad
- **Firmas Digitales:** Certificados firmados con RSA + SHA-256
- **Padding PKCS7:** Detecta manipulación en archivos cifrados
- **Validación de Certificados:** Verificación automática antes de usar claves públicas

### 3. Autenticación
- **PKI Completa:** Autoridad de Certificación verifica identidades
- **PBKDF2:** Derivación robusta de claves desde contraseñas (100,000 iteraciones)
- **Control de Acceso:** Solo destinatarios autorizados pueden descifrar

---

## Casos de Uso

### Caso 1: Compartir Documento Confidencial
**Escenario:** Enviar un contrato PDF a varios destinatarios de forma segura.

**Solución:**
- Cifrado híbrido con múltiples destinatarios
- Cada destinatario usa su propia contraseña
- El remitente también puede acceder (auto-inclusión)

### Caso 2: Proteger Archivo Personal
**Escenario:** Cifrar documentos sensibles en el disco duro.

**Solución:**
- Cifrado simétrico AES-256
- Clave guardada automáticamente de forma cifrada
- Recuperación posible con contraseña de usuario

### Caso 3: Verificar Autenticidad
**Escenario:** Confirmar que un archivo proviene realmente de quien dice ser.

**Solución:**
- Verificación de certificado digital
- Firma de la CA garantiza autenticidad
- Alerta si el certificado es inválido o falso

---

## Comparación con Estándares Industriales

| Característica | TYP3_$HIT          | PGP/GPG            | S/MIME        |
| :------------- | :----------------- | :----------------- | :------------ |
| Cifrado        | AES-256 + RSA-2048 | ✓ Similar          | ✓ Similar     |
| Firmas         | RSA + SHA-256      | ✓ Sí               | ✓ Sí          |
| PKI            | CA simulada        | Red de confianza   | CA jerárquica |
| Formato        | JSON + binario     | OpenPGP (RFC 4880) | PKCS#7/CMS    |
| Uso            | Archivos locales   | Email + archivos   | Email         |

**Conclusión:** TYP3_$HIT implementa los mismos conceptos fundamentales que sistemas profesionales, adaptados para propósitos educativos.

---

## Resultados y Logros

### ✅ Funcionalidades Implementadas (100%)

- ✓ **Cifrado Simétrico Completo:** AES-128/192/256 con 3 modos
- ✓ **Cifrado Asimétrico:** RSA-2048 con OAEP
- ✓ **Infraestructura PKI:** CA + Certificados + Firmas
- ✓ **Cifrado Híbrido:** Multi-usuario con AES + RSA
- ✓ **Gestión de Claves:** Almacenamiento seguro automático
- ✓ **Interfaz Gráfica:** Uso intuitivo con validaciones
- ✓ **Protección de Claves Privadas:** PBKDF2 con alta resistencia
- ✓ **Recuperación de Archivos:** Auto-inclusión del remitente

### 📊 Métricas de Seguridad

- **Fortaleza Criptográfica:** AES-256 (2^256 posibles claves)
- **Tamaño de Clave RSA:** 2048 bits (estándar actual)
- **Iteraciones PBKDF2:** 100,000 (resistencia a fuerza bruta)
- **Algoritmo Hash:** SHA-256 (resistente a colisiones)

---

## Estructura del Documento Completo

Para más detalles técnicos, consultar el documento `RESUMEN_COMPLETO.md` que incluye:

1. **Introducción y Objetivos** (esta sección)
2. **Arquitectura Detallada del Sistema**
3. **Documentación de Cada Módulo** (aes.py, rsa.py, certificacion.py)
4. **Flujos de Datos Completos** (Diagramas Mermaid)
5. **Protocolos de Seguridad** (PBKDF2, Firmas, Híbrido)
6. **Análisis de Seguridad** (Fortalezas y Limitaciones)
7. **Casos de Uso Prácticos**
8. **Comparación con PGP/GPG y S/MIME**
9. **Código de Ejemplo End-to-End**
10. **Conclusiones y Mejoras Futuras**

---

## Conclusión

El proyecto **TYP3_$HIT** representa una implementación completa y funcional de un sistema de seguridad criptográfica moderno, unificando tres entregas académicas en una aplicación cohesiva:

- **Entrega 1:** Fundamentos de cifrado simétrico (AES)
- **Entrega 2:** Intercambio seguro de claves (RSA)
- **Entrega 3:** Autenticación e identidad (PKI y firmas digitales)

Este sistema demuestra cómo conceptos teóricos de criptografía se aplican en software real para resolver problemas prácticos de **confidencialidad**, **integridad** y **autenticación**.

Aunque es un proyecto educativo, implementa técnicas y estándares utilizados en sistemas de producción actuales como PGP, S/MIME y sistemas bancarios, ofreciendo una base sólida para comprender la criptografía aplicada.

---

**Proyecto:** TYP3_$HIT  
**Asignatura:** Teoría de Códigos y Criptografía  
**Universidad:** Universidad de Almería  
**Fecha:** Diciembre 2025
