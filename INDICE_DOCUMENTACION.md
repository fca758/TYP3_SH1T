# Índice General de Documentación - TYP3_$HIT

Este documento sirve como índice maestro para navegar por toda la documentación del proyecto.

---

## 📖 Orden de Lectura Recomendado

Para nuevos lectores o evaluadores, se recomienda el siguiente orden:

1. **[README.md](README.md)** - Vista general del proyecto y estructura
2. **[INTRODUCCION.md](INTRODUCCION.md)** - Resumen ejecutivo y objetivos (5-10 min)
3. **[CRYPTOGRAPHY_WALKTHROUGH.md](CRYPTOGRAPHY_WALKTHROUGH.md)** - Diagramas visuales de flujos (10 min)
4. **[RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md)** - Documentación técnica completa (30-45 min)
5. **[PRESENTACION.md](PRESENTACION.md)** - Guía para presentación oral (referencia)
6. **[DIAPOSITIVAS.md](DIAPOSITIVAS.md)** - Contenido visual para slides (referencia)

---

## 📂 Documentos por Categoría

### Documentos de Introducción y Resumen

| Documento                              | Contenido                                              | Duración de Lectura |
| :------------------------------------- | :----------------------------------------------------- | :------------------ |
| **[README.md](README.md)**             | Vista general del proyecto, instalación, estructura    | 5 min               |
| **[INTRODUCCION.md](INTRODUCCION.md)** | Resumen ejecutivo con objetivos, arquitectura y logros | 10 min              |

### Documentación Técnica Completa

| Documento                                                      | Contenido                                                                                | Duración de Lectura |
| :------------------------------------------------------------- | :--------------------------------------------------------------------------------------- | :------------------ |
| **[RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md)**                 | Integración de las 3 entregas, análisis detallado de algoritmos, seguridad, casos de uso | 45 min              |
| **[CRYPTOGRAPHY_WALKTHROUGH.md](CRYPTOGRAPHY_WALKTHROUGH.md)** | Diagramas de flujo de procesos criptográficos (Mermaid)                                  | 15 min              |

### Materiales de Presentación

| Documento                              | Contenido                                       | Uso                    |
| :------------------------------------- | :---------------------------------------------- | :--------------------- |
| **[PRESENTACION.md](PRESENTACION.md)** | Guía completa (15 min) con notas para el orador | Ensayo de presentación |
| **[DIAPOSITIVAS.md](DIAPOSITIVAS.md)** | Contenido visual para 10 slides                 | Creación de PPT        |

---

## 📚 Contenido por Entrega

### Entrega 1: Cifrado Simétrico (AES)

**Archivo de implementación:** `aes.py`

**Documentación:**
- [RESUMEN_COMPLETO.md#Componente-1](RESUMEN_COMPLETO.md) - Sección "aes.py - Cifrado Simétrico"
- [CRYPTOGRAPHY_WALKTHROUGH.md#3](CRYPTOGRAPHY_WALKTHROUGH.md) - Diagrama "Cifrado Simétrico Manual"

**Temas cubiertos:**
- Algoritmo AES-128/192/256
- Modos CBC, CFB, OFB
- Padding PKCS7
- Generación de IV aleatorio
- Validación de claves

---

### Entrega 2: Cifrado Asimétrico (RSA)

**Archivo de implementación:** `rsa.py`

**Documentación:**
- [RESUMEN_COMPLETO.md#Componente-2](RESUMEN_COMPLETO.md) - Sección "rsa.py - Cifrado Asimétrico"
- [CRYPTOGRAPHY_WALKTHROUGH.md#1](CRYPTOGRAPHY_WALKTHROUGH.md) - Diagrama "Cifrado Híbrido" (integrado)

**Temas cubiertos:**
- RSA-2048
- Padding OAEP (vs PKCS1v15)
- Intercambio de claves
- Formato PEM

---

### Entrega 3: PKI y Certificación Digital

**Archivo de implementación:** `certificacion.py`

**Documentación:**
- [RESUMEN_COMPLETO.md#Componente-3](RESUMEN_COMPLETO.md) - Sección "certificacion.py - PKI y Firmas Digitales"
- [CRYPTOGRAPHY_WALKTHROUGH.md#1-y-2](CRYPTOGRAPHY_WALKTHROUGH.md) - Diagramas "Cifrado Híbrido" y "Descifrado"

**Temas cubiertos:**
- Autoridad de Certificación (CA)
- Generación de certificados
- Firma digital (RSA + SHA-256)
- Cifrado híbrido multi-usuario
- PBKDF2 para protección de claves

---

## 🔍 Búsqueda por Tema

### Algoritmos Criptográficos

| Algoritmo   | Dónde encontrarlo                                                                             |
| :---------- | :-------------------------------------------------------------------------------------------- |
| **AES**     | `aes.py`, [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección 1                                |
| **RSA**     | `rsa.py`, [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección 2                                |
| **SHA-256** | `certificacion.py`, [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección 3.2                    |
| **PBKDF2**  | `certificacion.py`, [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección "Protección de Claves" |

### Flujos de Proceso

| Proceso                   | Diagrama en                                                                                                                       |
| :------------------------ | :-------------------------------------------------------------------------------------------------------------------------------- |
| **Cifrado Híbrido**       | [CRYPTOGRAPHY_WALKTHROUGH.md](CRYPTOGRAPHY_WALKTHROUGH.md) + [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección "Flujos de Datos" |
| **Descifrado Híbrido**    | [CRYPTOGRAPHY_WALKTHROUGH.md](CRYPTOGRAPHY_WALKTHROUGH.md) + [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección "Flujos de Datos" |
| **Creación de Usuario**   | [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección 3.2                                                                            |
| **Firma de Certificados** | [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección "Protocolos de Seguridad"                                                      |

### Seguridad

| Tema                           | Ubicación                                                                       |
| :----------------------------- | :------------------------------------------------------------------------------ |
| **Análisis de Fortalezas**     | [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección "Análisis de Seguridad"      |
| **Limitaciones**               | [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) sección "Análisis de Seguridad"      |
| **Comparación con PGP/S/MIME** | [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) + [INTRODUCCION.md](INTRODUCCION.md) |

### Casos de Uso

| Caso                                 | Ubicación                                                                       |
| :----------------------------------- | :------------------------------------------------------------------------------ |
| **Compartir Documento Confidencial** | [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) + [INTRODUCCION.md](INTRODUCCION.md) |
| **Recuperación de Archivo**          | [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md)                                      |
| **Validación de Identidad**          | [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md)                                      |

---

## 📋 Documentos para Diferentes Audiencias

### Para Evaluadores Académicos

**Orden recomendado:**
1. [INTRODUCCION.md](INTRODUCCION.md) - Contexto y objetivos (10 min)
2. [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) - Evaluación técnica completa (45 min)
3. Revisar código fuente: `aes.py`, `rsa.py`, `certificacion.py`

**Puntos clave a evaluar:**
- Implementación correcta de algoritmos estándar (secciones del RESUMEN_COMPLETO)
- Integración de las tres entregas (todo el RESUMEN_COMPLETO)
- Seguridad del sistema (sección "Análisis de Seguridad")
- Comparación con estándares (sección "Comparación con Estándares")

---

### Para Estudiantes de Criptografía

**Orden recomendado:**
1. [README.md](README.md) - Vista general (5 min)
2. [CRYPTOGRAPHY_WALKTHROUGH.md](CRYPTOGRAPHY_WALKTHROUGH.md) - Visualización de flujos (15 min)
3. [INTRODUCCION.md](INTRODUCCION.md) - Conceptos fundamentales (10 min)
4. Experimentar con `main.py` (30 min)
5. [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md) - Profundización (1 hora)

**Conceptos para aprender:**
- Diferencia entre cifrado simétrico y asimétrico
- Por qué usar cifrado híbrido
- Importancia de IV, salt, padding
- Gestión segura de claves
- PKI y cadena de confianza

---

### Para Presentación Oral (15 minutos)

**Materiales:**
1. [PRESENTACION.md](PRESENTACION.md) - Guía completa con timings
2. [DIAPOSITIVAS.md](DIAPOSITIVAS.md) - Contenido para slides
3. Capturas de pantalla de la GUI (ejecutar `main.py`)
4. Demostración en vivo (opcional): cifrar/descifrar un archivo

**Estructura sugerida:**
- Slides 1-2: Introducción y objetivos (2 min)
- Slides 3-4: Algoritmos y arquitectura (3 min)
- Slides 5-6: Flujos de cifrado/descifrado (4 min)
- Slide 7: Demostración de funcionalidad (3 min)
- Slides 8-9: Código clave (2 min)
- Slide 10: Conclusiones (1 min)

---

## 💻 Archivos de Código Fuente

| Archivo            | Entrega     | LOC  | Descripción                                      |
| :----------------- | :---------- | :--- | :----------------------------------------------- |
| `aes.py`           | 1           | ~175 | Implementación AES con múltiples modos           |
| `rsa.py`           | 2           | ~85  | Cifrado/descifrado RSA con OAEP                  |
| `certificacion.py` | 3           | ~565 | CA, certificados, firma digital, cifrado híbrido |
| `typeShit.py`      | Integración | ~387 | Gestión de claves y almacenamiento seguro        |
| `typeShit_gui.py`  | UI          | ~426 | Interfaz gráfica completa (Tkinter)              |
| `user_keys.py`     | Auxiliar    | ~146 | Utilidades de gestión de claves                  |
| `main.py`          | Entrada     | ~6   | Punto de inicio de la aplicación                 |

**Total: ~1800 líneas de código**

---

## 📊 Estadísticas del Proyecto

### Documentación

- **Archivos de documentación:** 7
- **Palabras totales:** ~25,000
- **Diagramas Mermaid:** 5
- **Tablas comparativas:** 12+
- **Ejemplos de código:** 20+

### Implementación

- **Módulos principales:** 6
- **Funciones criptográficas:** 15+
- **Algoritmos implementados:** 8 (AES-128/192/256, RSA, SHA-256, PBKDF2, CBC/CFB/OFB)
- **Tipos de archivos soportados:** Todos (binarios)
- **Extensiones generadas:** `.enc`, `.hybenc`, `.cert`, `.key.enc`

### Seguridad

- **Tamaño de clave simétrica máxima:** 256 bits
- **Tamaño de clave asimétrica:** 2048 bits
- **Iteraciones PBKDF2:** 100,000
- **Algoritmo hash:** SHA-256
- **Nivel de seguridad equivalente:** ~112-128 bits

---

## 🔗 Enlaces Rápidos

### Documentación Principal
- [README.md](README.md)
- [INTRODUCCION.md](INTRODUCCION.md)
- [RESUMEN_COMPLETO.md](RESUMEN_COMPLETO.md)

### Documentación Técnica
- [CRYPTOGRAPHY_WALKTHROUGH.md](CRYPTOGRAPHY_WALKTHROUGH.md)
- [Código fuente en GitHub](.) (este directorio)

### Presentación
- [PRESENTACION.md](PRESENTACION.md)
- [DIAPOSITIVAS.md](DIAPOSITIVAS.md)

---

## ✅ Checklist de Revisión

### Para Entrega Final

- [x] Código funcional y probado
- [x] Documentación completa (README, INTRODUCCION, RESUMEN_COMPLETO)
- [x] Diagramas de flujo (CRYPTOGRAPHY_WALKTHROUGH)
- [x] Material de presentación (PRESENTACION, DIAPOSITIVAS)
- [x] Comentarios en código fuente
- [x] Integración de las 3 entregas
- [x] Análisis de seguridad
- [x] Comparación con estándares
- [x] Ejemplos de uso

---

**Última actualización:** Diciembre 2025  
**Proyecto:** TYP3_$HIT  
**Asignatura:** Teoría de Códigos y Criptografía  
**Universidad:** Universidad de Almería
