# Walkthrough: Métodos Criptográficos y Flujos de Datos

Este documento detalla los procesos internos de los diferentes métodos de cifrado utilizados en la aplicación, ilustrados mediante diagramas de flujo.

---

## 1. Cifrado Híbrido (Multi-Usuario)

Este es el método principal para compartir archivos de forma segura. Combina la eficiencia de **AES** para cifrar datos con la seguridad de **RSA** para intercambiar la clave.

### 📝 Proceso de Cifrado
El usuario "Alice" quiere enviar un archivo a "Bob" y "Charlie".

```mermaid
flowchart TD
    Start([Inicio: Alice selecciona Archivo y Destinatarios]) --> GenKey[Generar Clave Aleatoria AES-256]
    
    subgraph SImetrico [Cifrado de Datos]
    GenKey --> EncFile[Cifrar Archivo con Clave AES]
    EncFile --> FileData[Datos Cifrados]
    end
    
    subgraph Asimetrico [Cifrado de Clave]
    GenKey --> LoopDest{Para cada destinatario}
    LoopDest -->|Bob| PubBob[Obtener Public Key Bob]
    LoopDest -->|Charlie| PubCharlie[Obtener Public Key Charlie]
    
    PubBob --> EncKey1[Cifrar Clave AES con RSA Public]
    PubCharlie --> EncKey2[Cifrar Clave AES con RSA Public]
    end
    
    FileData --> Package[Empaquetar JSON]
    EncKey1 --> Package
    EncKey2 --> Package
    
    Package --> FinalFile([Archivo Final .hybenc])
    
    style Start fill:#f9f,stroke:#333
    style FinalFile fill:#ccf,stroke:#333
    style GenKey fill:#ff9,stroke:#333
```

### 🔓 Proceso de Descifrado
"Bob" recibe el archivo cifrado y quiere leerlo.

```mermaid
flowchart TD
    Start([Inicio: Bob abre archivo .hybenc]) --> ReadHeader[Leer Cabecera JSON]
    ReadHeader --> FindRec{¿Está Bob en destinatarios?}
    
    FindRec -->|No| Error([Error: Acceso Denegado])
    FindRec -->|Si| GetEncKey[Extraer Clave AES Cifrada para Bob]
    
    subgraph Auth [Autenticación]
    GetEncKey --> AskPass[Solicitar Contraseña de Bob]
    AskPass --> ValPass{Validar Contraseña}
    ValPass -->|Invalida| Error
    end
    
    subgraph PrivateKey [Recuperación Clave Privada]
    ValPass -->|Valida| LoadPrivEnc[Leer bob.key.enc]
    LoadPrivEnc --> DecPriv[Descifrar Clave Privada RSA usando Password]
    end
    
    subgraph Decrypt [Descifrado]
    DecPriv --> DecAESKey[Descifrar Clave AES de Sesión]
    DecAESKey --> DecFile[Descifrar Contenido del Archivo]
    end
    
    DecFile --> Success([Archivo Descifrado Exitosamente])
    
    style Start fill:#f9f,stroke:#333
    style Error fill:#f99,stroke:#333
    style Success fill:#9f9,stroke:#333
```

---

## 2. Protección de Claves (Almacén de Usuario)

Sistema diseñado para almacenar las claves AES generadas manualmente o automáticamente, cifrándolas de forma que solo el usuario propietario pueda acceder a ellas.

### 🔐 Flujo de Seguridad: Cadena de Confianza

Este diagrama muestra cómo se protegen las claves AES almacenadas.

```mermaid
flowchart TD
    Pass([User Password]) -->|PBKDF2| KEK[Key Encryption Key]
    KEK -->|AES-256| RSAPriv[RSA Private Key]
    RSAPriv -->|SHA-256 Hash| AESKey[Storage AES Key]
    AESKey -->|AES-CBC| Database[("Base de Datos de Claves (.enc)")]
    
    subgraph Nivel1 [Nivel 1: Autenticación]
    Pass
    KEK
    end
    
    subgraph Nivel2 [Nivel 2: Identidad]
    RSAPriv
    end
    
    subgraph Nivel3 [Nivel 3: Almacenamiento]
    AESKey
    Database
    end
    
    style Pass fill:#f9f,stroke:#333
    style RSAPriv fill:#ccf,stroke:#333
    style Database fill:#ff9,stroke:#333
```

1.  **Nivel 1:** La contraseña del usuario desbloquea su **Clave Privada RSA**.
2.  **Nivel 2:** La Clave Privada RSA (que es única e intransferible) se usa para derivar matemáticamente una **Clave de Almacenamiento**.
3.  **Nivel 3:** Esa clave cifra el archivo JSON que contiene todas las claves AES guardadas.

---

## 3. Cifrado Simétrico Manual (AES Tradicional)

Cifrado directo de un archivo usando una clave proporcionada (o generada) manualmente.

```mermaid
flowchart TD
    Start([Inicio: Usuario ingresa Datos]) --> Inputs[Archivo + Clave + Algoritmo]
    
    subgraph Prep [Preparación]
    Inputs --> Norm[Normalizar Clave a Bytes]
    Norm --> GenIV[Generar IV Aleatorio]
    end
    
    subgraph Enc [Cifrado]
    GenIV --> DoEnc[AES Encrypt CBC/CFB/OFB]
    DoEnc --> OutFile([Archivo Cifrado .enc])
    end
    
    subgraph Storage [Auto-Guardado]
    OutFile --> AskPass[Pedir Contraseña Usuario Activo]
    AskPass --> Val{¿Contraseña Correcta?}
    Val -->|No| Skip[No guardar clave]
    Val -->|Si| CalcKey[Derivar Storage Key de RSA Privada]
    CalcKey --> SaveKey[(Guardar en Almacén Seguro)]
    end
    
    Skip --> End([Fin])
    SaveKey --> End
    
    style Start fill:#f9f,stroke:#333
    style OutFile fill:#9f9,stroke:#333
    style SaveKey fill:#ff9,stroke:#333
```

---

## Resumen de Archivos Generados

| Tipo de Cifrado | Extensión | Contenido |
| :--- | :--- | :--- |
| **Híbrido** | `.hybenc` | Metadatos JSON (Keys cifradas con RSA) + Binario AES |
| **Simétrico** | `.enc` / `.aes` | Solo datos cifrados (IV suele ir prepend o separado) |
| **Clave Privada** | `.key.enc` | Salt + IV + Clave Privada RSA (Cifrada con Password) |
| **Almacén Claves** | `_keys.enc` | IV + Lista JSON de claves AES (Cifrada con RSA-derived key) |
