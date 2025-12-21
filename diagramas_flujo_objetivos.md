# Diagramas de Flujo - Objetivos del Sistema Criptográfico

Este documento presenta los diagramas de flujo correspondientes a cada uno de los objetivos del sistema de gestión criptográfica.

---

## 1. Aplicación de Escritorio con Interfaz Gráfica

```mermaid
flowchart TD
    A[Inicio] --> B[Cargar módulos Python]
    B --> C[Inicializar tkinter/PyQt]
    C --> D[Crear ventana principal]
    D --> E[Configurar menús y controles]
    E --> F[Cargar módulos criptográficos]
    F --> G{Usuario autenticado?}
    G -->|No| H[Mostrar pantalla de login]
    H --> I[Solicitar credenciales]
    I --> J{Credenciales válidas?}
    J -->|No| I
    J -->|Sí| K[Cargar interfaz principal]
    G -->|Sí| K
    K --> L[Mostrar opciones: Cifrar/Descifrar/Certificados/Claves]
    L --> M{Acción seleccionada}
    M --> N[Ejecutar módulo correspondiente]
    N --> O[Mostrar resultados en GUI]
    O --> P{Continuar?}
    P -->|Sí| L
    P -->|No| Q[Fin]
```

---

## 2. Cifrado Simétrico AES (CBC, CFB, OFB)

```mermaid
flowchart TD
    A[Inicio Cifrado AES] --> B[Recibir datos a cifrar]
    B --> C[Solicitar clave de cifrado]
    C --> D{Seleccionar modo de operación}
    D -->|CBC| E1[Modo CBC]
    D -->|CFB| E2[Modo CFB]
    D -->|OFB| E3[Modo OFB]
    
    E1 --> F[Generar IV aleatorio]
    E2 --> F
    E3 --> F
    
    F --> G[Aplicar padding PKCS7]
    G --> H[Crear cifrador AES con modo seleccionado]
    H --> I[Cifrar datos por bloques]
    I --> J[Concatenar IV + datos cifrados]
    J --> K[Almacenar/Transmitir resultado]
    K --> L[Fin Cifrado]
    
    subgraph "Descifrado"
        M[Inicio Descifrado] --> N[Extraer IV del mensaje]
        N --> O[Crear descifrador con mismo modo]
        O --> P[Descifrar bloques]
        P --> Q[Eliminar padding]
        Q --> R[Datos originales recuperados]
    end
```

---

## 3. Generación de Vectores de Inicialización (IV)

```mermaid
flowchart TD
    A[Inicio Generación IV] --> B[Determinar tamaño del bloque AES]
    B --> C[Tamaño = 16 bytes / 128 bits]
    C --> D[Invocar generador criptográfico seguro]
    D --> E[os.urandom o secrets.token_bytes]
    E --> F[Generar 16 bytes aleatorios]
    F --> G{IV único generado?}
    G -->|No| D
    G -->|Sí| H[Almacenar IV temporalmente]
    H --> I{IV para cifrar o descifrar?}
    I -->|Cifrar| J[Prepender IV al ciphertext]
    I -->|Descifrar| K[Extraer IV del ciphertext]
    J --> L[IV disponible para operación]
    K --> L
    L --> M[Fin]
    
    subgraph "Propiedades del IV"
        N[Aleatorio]
        O[No predecible]
        P[Único por operación]
        Q[No requiere ser secreto]
    end
```

---

## 4. Algoritmo RSA con Relleno OAEP

```mermaid
flowchart TD
    A[Inicio RSA-OAEP] --> B{Operación?}
    
    B -->|Generar par de claves| C[Especificar tamaño: 2048/4096 bits]
    C --> D[Generar números primos p, q]
    D --> E[Calcular n = p * q]
    E --> F[Calcular φn = p-1 * q-1]
    F --> G[Seleccionar exponente público e]
    G --> H[Calcular exponente privado d]
    H --> I[Exportar clave pública: n, e]
    I --> J[Exportar clave privada: n, d]
    
    B -->|Cifrar clave simétrica| K[Recibir clave AES a proteger]
    K --> L[Cargar clave pública del destinatario]
    L --> M[Aplicar relleno OAEP con SHA-256]
    M --> N[Cifrar: C = M^e mod n]
    N --> O[Clave AES cifrada lista]
    
    B -->|Descifrar clave simétrica| P[Recibir clave AES cifrada]
    P --> Q[Cargar clave privada propia]
    Q --> R[Descifrar: M = C^d mod n]
    R --> S[Verificar y eliminar relleno OAEP]
    S --> T[Clave AES recuperada]
    
    O --> U[Fin]
    T --> U
    J --> U
```

---

## 5. Autoridad de Certificación (CA) Local

```mermaid
flowchart TD
    A[Inicio Creación CA] --> B[Generar par de claves RSA para CA]
    B --> C[Crear certificado raíz X.509]
    C --> D[Establecer campos del certificado]
    D --> E[Subject: CN=CA Local]
    E --> F[Issuer: CN=CA Local / autofirmado]
    F --> G[Período de validez: 10 años]
    G --> H[Extensiones: CA=True, KeyUsage]
    H --> I[Firmar certificado con clave privada CA]
    I --> J[Almacenar certificado raíz]
    J --> K[Proteger clave privada de CA]
    K --> L[CA lista para firmar certificados]
    
    subgraph "Proceso de Firma"
        M[Recibir solicitud CSR] --> N[Verificar identidad del solicitante]
        N --> O{Identidad válida?}
        O -->|No| P[Rechazar solicitud]
        O -->|Sí| Q[Crear certificado de usuario]
        Q --> R[Vincular clave pública del usuario]
        R --> S[Firmar con clave privada de CA]
        S --> T[Emitir certificado firmado]
    end
    
    L --> M
    T --> U[Fin]
    P --> U
```

---

## 6. Emisión de Certificados Digitales

```mermaid
flowchart TD
    A[Inicio Emisión Certificado] --> B[Usuario genera par de claves RSA]
    B --> C[Usuario crea CSR con datos de identidad]
    C --> D[Incluir: Nombre, Email, Organización]
    D --> E[Firmar CSR con clave privada del usuario]
    E --> F[Enviar CSR a la CA]
    
    F --> G[CA recibe CSR]
    G --> H[Verificar firma del CSR]
    H --> I{Firma válida?}
    I -->|No| J[Rechazar CSR]
    I -->|Sí| K[Extraer clave pública del CSR]
    K --> L[Crear certificado X.509]
    
    L --> M[Establecer campos]
    M --> N[Subject: datos del usuario]
    N --> O[Issuer: datos de la CA]
    O --> P[Serial Number único]
    P --> Q[Validez: fecha inicio - fecha fin]
    Q --> R[Extensiones: KeyUsage, ExtKeyUsage]
    
    R --> S[Firmar certificado con clave privada CA]
    S --> T[Generar certificado en formato PEM]
    T --> U[Entregar certificado al usuario]
    U --> V[Usuario almacena certificado]
    V --> W[Fin]
    J --> W
```

---

## 7. Protección de Claves Privadas con PBKDF2

```mermaid
flowchart TD
    A[Inicio Protección Clave Privada] --> B[Recibir clave privada del usuario]
    B --> C[Solicitar contraseña al usuario]
    C --> D[Generar salt aleatorio de 16 bytes]
    D --> E[Configurar PBKDF2]
    E --> F[Algoritmo: SHA-256]
    F --> G[Iteraciones: 100,000+]
    G --> H[Longitud salida: 32 bytes]
    H --> I[Derivar clave de cifrado desde contraseña]
    I --> J[Clave derivada = PBKDF2 salt, password, iterations]
    J --> K[Cifrar clave privada con AES-256]
    K --> L[Almacenar: salt + clave privada cifrada]
    L --> M[Fin Protección]
    
    subgraph "Desprotección"
        N[Solicitar contraseña] --> O[Leer salt almacenado]
        O --> P[Derivar clave con PBKDF2]
        P --> Q[Descifrar clave privada]
        Q --> R{Descifrado exitoso?}
        R -->|No| S[Contraseña incorrecta]
        R -->|Sí| T[Clave privada disponible en memoria]
    end
```

---

## 8. Sistema de Cifrado Híbrido (AES + RSA)

```mermaid
flowchart TD
    A[Inicio Cifrado Híbrido] --> B[Seleccionar archivo a cifrar]
    B --> C[Generar clave AES aleatoria de 256 bits]
    C --> D[Generar IV aleatorio de 16 bytes]
    D --> E[Cifrar archivo con AES-CBC]
    E --> F[Obtener certificado del destinatario]
    F --> G[Extraer clave pública RSA del certificado]
    G --> H[Cifrar clave AES con RSA-OAEP]
    H --> I[Crear paquete cifrado]
    I --> J[Estructura: Clave AES cifrada + IV + Datos cifrados]
    J --> K[Almacenar archivo cifrado]
    K --> L[Fin Cifrado]
    
    subgraph "Descifrado Híbrido"
        M[Recibir archivo cifrado] --> N[Extraer clave AES cifrada]
        N --> O[Cargar clave privada del destinatario]
        O --> P[Descifrar clave AES con RSA-OAEP]
        P --> Q[Extraer IV del paquete]
        Q --> R[Descifrar datos con AES-CBC]
        R --> S[Archivo original recuperado]
    end
```

---

## 9. Cifrado para Múltiples Destinatarios

```mermaid
flowchart TD
    A[Inicio Cifrado Multi-Destinatario] --> B[Seleccionar archivo a cifrar]
    B --> C[Generar clave AES única para el archivo]
    C --> D[Cifrar archivo con AES]
    D --> E[Seleccionar lista de destinatarios]
    E --> F[Para cada destinatario]
    
    F --> G[Obtener certificado del destinatario i]
    G --> H[Verificar certificado con CA]
    H --> I{Certificado válido?}
    I -->|No| J[Excluir destinatario]
    I -->|Sí| K[Extraer clave pública]
    K --> L[Cifrar clave AES con RSA-OAEP]
    L --> M[Agregar a lista de claves cifradas]
    M --> N{Más destinatarios?}
    N -->|Sí| F
    N -->|No| O[Crear paquete multi-destinatario]
    
    O --> P[Estructura del paquete]
    P --> Q[Header: número de destinatarios]
    Q --> R[Lista: ID destinatario + clave AES cifrada]
    R --> S[Body: IV + archivo cifrado]
    S --> T[Almacenar paquete]
    T --> U[Fin]
    J --> N
```

---

## 10. Recuperación Segura de Archivos

```mermaid
flowchart TD
    A[Inicio Sistema de Recuperación] --> B{Operación?}
    
    B -->|Almacenar claves| C[Generar clave de sesión AES]
    C --> D[Cifrar archivo con clave de sesión]
    D --> E[Para cada destinatario autorizado]
    E --> F[Cifrar clave de sesión con RSA del destinatario]
    F --> G[Almacenar asociación: archivo ID + usuario ID + clave cifrada]
    G --> H[Guardar en base de datos segura]
    H --> I{Más destinatarios?}
    I -->|Sí| E
    I -->|No| J[Registro de claves completado]
    
    B -->|Recuperar archivo| K[Usuario solicita acceso a archivo]
    K --> L[Autenticar usuario]
    L --> M{Autenticación válida?}
    M -->|No| N[Acceso denegado]
    M -->|Sí| O[Buscar clave cifrada para este usuario]
    O --> P{Clave encontrada?}
    P -->|No| Q[Usuario no autorizado]
    P -->|Sí| R[Solicitar clave privada del usuario]
    R --> S[Descifrar clave de sesión con RSA]
    S --> T[Descifrar archivo con clave de sesión]
    T --> U[Archivo recuperado exitosamente]
    
    J --> V[Fin]
    N --> V
    Q --> V
    U --> V
```

---

## Resumen Visual del Sistema Completo

```mermaid
flowchart LR
    subgraph "Capa de Interfaz"
        A[GUI Python tkinter/PyQt]
    end
    
    subgraph "Capa de Criptografía Simétrica"
        B[AES-256]
        C[Modos: CBC/CFB/OFB]
        D[Generación IV]
    end
    
    subgraph "Capa de Criptografía Asimétrica"
        E[RSA-2048/4096]
        F[Relleno OAEP]
        G[Cifrado Híbrido]
    end
    
    subgraph "Capa de Gestión de Identidad"
        H[CA Local]
        I[Certificados X.509]
        J[Validación de Usuarios]
    end
    
    subgraph "Capa de Protección de Claves"
        K[PBKDF2]
        L[Almacenamiento Seguro]
        M[Recuperación de Claves]
    end
    
    A --> B
    A --> E
    A --> H
    B --> C
    C --> D
    E --> F
    F --> G
    H --> I
    I --> J
    G --> K
    K --> L
    L --> M
```

---

> [!NOTE]
> Estos diagramas representan el flujo lógico de cada objetivo. La implementación real puede variar según las bibliotecas utilizadas (como `cryptography` de Python) y los requisitos específicos del sistema.
