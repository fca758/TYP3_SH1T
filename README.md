# TYP3_$HIT 🔐
## Sistema de Cifrado Híbrido y Gestión de Certificados Digitales

**TYP3_$HIT** es nuestra aplicación criptográfica desarrollada como proyecto final para la asignatura de **Teoría de Códigos y Criptografía** en la Universidad de Almería.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/Cryptography-Latest-green.svg)](https://cryptography.io/)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)]()

---

## 📋 Descripción

Sistema completo de seguridad criptográfica que integra:

- **Cifrado Simétrico** - AES-128/192/256 en modos CBC, CFB, OFB
- **Cifrado Asimétrico** - RSA-2048 con padding OAEP
- **Infraestructura PKI** - Autoridad de Certificación y firmas digitales
- **Cifrado Híbrido** - Compartición segura de archivos entre múltiples usuarios

---

## 📚 Documentación

### Documentos Principales

| Documento                                                      | Descripción                                                      |
| :------------------------------------------------------------- | :--------------------------------------------------------------- |
| **[INTRODUCCION.md](INTRODUCCION.md)**                         | Resumen ejecutivo del proyecto, objetivos y arquitectura         |
| **[RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md)**                 | Documentación técnica detallada de todas las entregas integradas |
| **[CRYPTOGRAPHY_WALKTHROUGH.md](CRYPTOGRAPHY_WALKTHROUGH.md)** | Diagramas de flujo de los procesos criptográficos                |
| **[PRESENTACION.md](PRESENTACION.md)**                         | Guía de presentación (15 minutos)                                |
| **[DIAPOSITIVAS.md](DIAPOSITIVAS.md)**                         | Contenido visual para diapositivas                               |

### Recomendación de Lectura

1. **Inicio rápido:** Lee [INTRODUCCION.md](INTRODUCCION.md) para entender el proyecto
2. **Detalles técnicos:** Consulta [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) para implementación completa
3. **Visualización:** Revisa [CRYPTOGRAPHY_WALKTHROUGH.md](CRYPTOGRAPHY_WALKTHROUGH.md) para diagramas de flujo

---

## 🚀 Inicio Rápido

### Requisitos

```bash
Python 3.11+
pip install cryptography
```

### Ejecución

```bash
python main.py
```

Esto abrirá la interfaz gráfica con las siguientes opciones:
- Cifrado/Descifrado Simétrico (AES)
- Cifrado/Descifrado Híbrido (Multi-usuario)
- Gestión de Certificados
- Almacén de Claves

---

## 🏗️ Estructura del Proyecto

```
TYP3_SH1T/
├── main.py                      # Punto de entrada de la aplicación
├── typeShit_gui.py              # Interfaz gráfica (Tkinter)
├── typeShit.py                  # Lógica de negocio y gestión de claves
├── aes.py                       # Módulo de cifrado simétrico (Entrega 1)
├── rsa.py                       # Módulo de cifrado asimétrico (Entrega 2)
├── certificacion.py             # Sistema PKI y firmas digitales (Entrega 3)
├── user_keys.py                 # Utilidades auxiliares
│
├── Keys/                        # Almacén de claves AES cifradas
│   ├── public.pem
│   ├── private.pem
│   ├── keys.txt.enc
│   └── keys.txt.key
│
├── certs/                       # Sistema de certificación
│   ├── license.txt              # Clave maestra de la CA
│   ├── ca/                      # Autoridad de Certificación
│   │   ├── ca_public.pem
│   │   └── ca_private.enc
│   └── users/                   # Certificados de usuarios
│       ├── [usuario].cert
│       └── [usuario].key.enc
│
└── Documentación/
    ├── INTRODUCCION.md
    ├── RESUMEN_COMPLETO.md
    ├── CRYPTOGRAPHY_WALKTHROUGH.md
    ├── PRESENTACION.md
    └── DIAPOSITIVAS.md
```

---

## 🔐 Características de Seguridad

- ✅ **AES-256-CBC** para cifrado de archivos
- ✅ **RSA-2048-OAEP** para intercambio de claves
- ✅ **PBKDF2** (100k iteraciones) para derivación de claves
- ✅ **SHA-256** para firmas digitales
- ✅ **IV aleatorio** único por cada operación
- ✅ **Padding PKCS7** para integridad
- ✅ **Claves privadas protegidas** con contraseña

---

## 📦 Entregas Integradas

| Entrega | Módulo             | Contenido                            |
| :------ | :----------------- | :----------------------------------- |
| **1**   | `aes.py`           | Cifrado simétrico AES-128/192/256    |
| **2**   | `rsa.py`           | Cifrado asimétrico RSA-2048          |
| **3**   | `certificacion.py` | PKI, certificados y firmas digitales |

---

## 👥 Autores

Proyecto desarrollado para la asignatura de **Teoría de Códigos y Criptografía**  
Universidad de Almería - 2025

---

## 📄 Licencia

Este proyecto es de uso educativo para la asignatura de Teoría de Códigos y Criptografía.

---

## 🙏 Agradecimientos

- Profesor de la asignatura por la guía durante el desarrollo
- Documentación de `cryptography.io` por los ejemplos claros
- Estándares NIST para las especificaciones técnicas
