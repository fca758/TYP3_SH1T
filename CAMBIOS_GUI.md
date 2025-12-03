# CAMBIOS EN LA INTERFAZ GRÁFICA (GUI)

## Resumen de Modificaciones

Se ha restructurado completamente la interfaz de usuario para mejorar la interacción y flujo de trabajo:

### ✅ Cambios Principales

#### 1. **Reorganización Superior: Usuario Activo (Nueva)**

**Antes:**
```
Acción: [encrypt ▼]
```

**Ahora:**
```
Usuario activo: [Seleccionar usuario... ▼]  [⟳ Refrescar]
                ⚙ Gestionar certificados (enlace)

Acción: [encrypt ▼]
```

**¿Qué significa?**
- Desplegable de **todos los usuarios válidos** disponibles
- Botón **Refrescar** para actualizar la lista
- **Enlace "Gestionar certificados"** directamente accesible (no como botón separado)

---

#### 2. **Renombrar Botón: "Seleccionar destinatarios" → "Cifrado múltiple"**

**Antes:**
```
[Buscar clave guardada] [Gestionar certificados] [Seleccionar destinatarios]
```

**Ahora:**
```
[Cifrado múltiple] [Buscar clave guardada]
```

**Cambios:**
- ✓ Nombre más intuitivo: **"Cifrado múltiple"**
- ✓ Color destacado: verde (#27ae60) para indicar acción importante
- ✓ Posición: movido a la izquierda (column=0)
- ✓ Mejor accesibilidad: el botón es más visible

---

#### 3. **Mejora del Diálogo "Cifrado Múltiple"**

**Interfaz mejorada:**
```
┌─────────────────────────────────────────┐
│  Cifrado múltiple - Seleccionar...      │
├─────────────────────────────────────────┤
│                                         │
│ Selecciona los usuarios que podrán      │
│ descifrar el archivo:                   │
│                                         │
│ ┌─────────────────────────────────────┐ │
│ │ ☑ María                             │ │
│ │ ☑ Pedro                             │ │
│ │ ☐ Juan                              │ │
│ │ ☐ Admin                             │ │
│ └─────────────────────────────────────┘ │
│                                         │
│  [✓ Confirmar]  [✕ Cancelar]          │
│                                         │
└─────────────────────────────────────────┘
```

**Mejoras:**
- Título descriptivo
- Listbox con checkboxes para múltiple selección
- Indicadores visuales: ✓ para confirmar, ✕ para cancelar
- Validación: requiere al menos 1 destinatario
- Mensaje de confirmación con resumen en la salida

---

#### 4. **Reorganización de "Gestionar Certificados"**

**Antes:** Botón en la fila de botones inferior
```
[Gestionar certificados] (en fila de botones)
```

**Ahora:** Enlace en la parte superior
```
Usuario activo: [Seleccionar usuario... ▼]
                ⚙ Gestionar certificados  ← Enlace clickeable
```

**Ventajas:**
- ✓ Acceso rápido desde la parte superior
- ✓ No ocupa espacio en la fila de botones
- ✓ Más ergonómico: menos movimiento del cursor

---

#### 5. **Mejora del Diálogo "Gestionar Certificados"**

**Nuevo diseño modular:**

```
┌─────────────────────────────────────────────────────┐
│ Gestionar certificados                              │
├─────────────────────────────────────────────────────┤
│                                                     │
│ ⚙ AUTORIDAD CERTIFICADORA (CA)                     │
│ ┌───────────────────────────────────────────────┐   │
│ │ Número de licencia: [________________]         │   │
│ │                    [Crear CA]                 │   │
│ └───────────────────────────────────────────────┘   │
│                                                     │
│ 👤 CREAR USUARIO                                   │
│ ┌───────────────────────────────────────────────┐   │
│ │ Identidad:        [_______________]           │   │
│ │ Contraseña:       [_______________]           │   │
│ │ Licencia (firma): [_______________]           │   │
│ │                  [Crear usuario]              │   │
│ └───────────────────────────────────────────────┘   │
│                                                     │
│ 📋 CERTIFICADOS DISPONIBLES                        │
│ ┌───────────────────────────────────────────────┐   │
│ │ María                [✓ VÁLIDO]               │   │
│ │ Pedro                [✓ VÁLIDO]               │   │
│ │ Juan                 [✕ INVÁLIDO]             │   │
│ └───────────────────────────────────────────────┘   │
│                                                     │
│ [🔄 Refrescar] [🗑 Eliminar usuario] [Cerrar]     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Mejoras:**

1. **Secciones Claras:**
   - CA (Autoridad Certificadora)
   - Crear Usuario
   - Certificados Disponibles

2. **Iconos Descriptivos:**
   - ⚙ para configuración
   - 👤 para usuarios
   - 📋 para certificados
   - 🔄 para refrescar
   - 🗑 para eliminar

3. **Mejor Visualización:**
   - Cada sección en frame separado con fondo diferente
   - Scrollbar para lista de certificados
   - Botones de colores significativos:
     - Verde para "Crear"
     - Azul para "Crear CA"
     - Rojo para "Eliminar"

4. **Nueva Funcionalidad:**
   - **✓ Botón "Eliminar usuario"**: permite eliminar usuarios y sus certificados
   - **✓ Confirmación antes de eliminar**: protección contra eliminaciones accidentales
   - **✓ Auto-actualización**: tras crear/eliminar, se refresca la lista

---

## Nuevo Flujo de Trabajo

### Escenario 1: Crear CA y Usuarios por Primera Vez

```
1. Click en enlace "⚙ Gestionar certificados"
   ↓
2. En sección "CA":
   - Introducir: "ABC-123-XYZ"
   - Click [Crear CA]
   ↓
3. En sección "Crear usuario":
   - Identidad: "María"
   - Contraseña: "mi_contraseña"
   - Licencia: "ABC-123-XYZ"
   - Click [Crear usuario]
   ↓
4. Repetir paso 3 para "Pedro", "Juan", etc.
   ↓
5. Click [Cerrar]
   ↓
6. El desplegable "Usuario activo" se auto-actualiza
   mostrando: María, Pedro, Juan
```

### Escenario 2: Cifrado Múltiple

```
1. Usuario activo: [María ▼]  ← Seleccionar usuario
   
2. Click [Cifrado múltiple]
   ↓
3. Seleccionar destinatarios:
   ☑ María
   ☑ Pedro
   ☐ Juan
   ↓
4. Click [✓ Confirmar]
   ↓
5. Salida muestra:
   "✓ Cifrado múltiple configurado
    Destinatarios: María, Pedro
    Próximo archivo será cifrado para 2 usuario(s)."
   ↓
6. Seleccionar archivo y Click [Ejecutar]
   ↓
7. Se cifra para María y Pedro únicamente
```

### Escenario 3: Eliminar Usuario

```
1. Click en enlace "⚙ Gestionar certificados"
   ↓
2. Sección "CERTIFICADOS DISPONIBLES":
   - Seleccionar usuario (ej: Juan)
   ↓
3. Click [🗑 Eliminar usuario]
   ↓
4. Confirmación: "¿Eliminar usuario 'Juan' y su certificado?"
   ↓
5. Si OK:
   - Se elimina: juan.cert y juan.key.enc
   - Se refresca la lista
   - Se actualiza el desplegable superior
```

---

## Cambios de Comportamiento en la GUI

### Inicialización

```python
self.after(100, self.refresh_user_list)  # Cargar usuarios al iniciar
```

El desplegable se llena automáticamente con usuarios válidos al abrir la aplicación.

### Método Nuevo: `refresh_user_list()`

```python
def refresh_user_list(self) -> None:
    """Recarga la lista de usuarios disponibles en el combobox."""
    certs = certificacion.list_certificates()
    user_list = [c.get('identity') for c in certs if c.get('valid')]
    self.user_combo['values'] = user_list
```

- Se ejecuta al iniciar
- Se ejecuta al hacer click en "⟳ Refrescar"
- Se ejecuta después de crear/eliminar usuarios
- Mantiene la selección anterior si aún existe

### Método Actualizado: `select_recipients()` → "Cifrado múltiple"

Cambios:
- Validación: requiere mínimo 1 selección
- Mejor UX: confirmación visual en la salida
- Diálogo más grande y legible (500x400)

### Método Mejorado: `manage_certificates()`

Cambios:
- Diálogo más grande (700x550) para mejor legibilidad
- Secciones separadas y claramente etiquetadas
- Botón nuevo: "🗑 Eliminar usuario"
- Auto-actualización tras crear/eliminar
- Mejor manejo de errores

---

## Estructura Visual de la GUI (Después de Cambios)

```
┌──────────────────────────────────────────────────────────┐
│ TYP3_SH1T                                                │
├──────────────────────────────────────────────────────────┤
│                                                          │
│ Usuario activo: [María ▼]              [⟳ Refrescar]   │
│                ⚙ Gestionar certificados (enlace)        │
│                                                          │
│ Acción: [encrypt ▼]                                     │
│ Algoritmo: [AES-256 ▼]    Modo: [CBC ▼]               │
│ Archivo entrada: [________] [Examinar]                  │
│ Clave: [__________________]             [Generar]       │
│                                                          │
│ [Cifrado múltiple] [Buscar clave guardada]             │
│                                                          │
│ Salida:                                                  │
│ ┌──────────────────────────────────────────────────┐   │
│ │ ✓ Cifrado múltiple configurado                  │   │
│ │ Destinatarios: María, Pedro                     │   │
│ │ Próximo archivo será cifrado para 2 usuario(s) │   │
│ │                                                  │   │
│ └──────────────────────────────────────────────────┘   │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Resumen de Beneficios

| Aspecto | Antes | Después |
|---------|-------|---------|
| **Acceso a certificados** | Botón separado | Enlace integrado en la parte superior |
| **Seleccionar usuario** | No disponible | Desplegable en la parte superior |
| **Cifrado múltiple** | Genérico | Botón destacado con nombre intuitivo |
| **Eliminar usuarios** | No disponible | Integrado en "Gestionar certificados" |
| **Refrescar usuarios** | Manual | Botón + Auto-actualización |
| **Interfaz | Plana | Secciones claramente diferenciadas |
| **Iconos** | Mínimos | Descriptivos y visuales |
| **Tamaño diálogos** | Compactos | Optimizados para legibilidad |
| **Flujo de trabajo** | Disperso | Lógico y organizado |

---

## Notas Técnicas

1. **Colores utilizados:**
   - Verde (#27ae60): Acciones confirmativas
   - Azul (#3498db): Información
   - Rojo (#e74c3c): Acciones peligrosas
   - Gris (#95a5a6): Acciones neutras
   - Oscuro (#34495e): Cerrar

2. **Emojis utilizados:**
   - ⚙ = Configuración
   - 👤 = Usuario
   - 📋 = Certificados
   - 🔄 = Refrescar
   - 🗑 = Eliminar
   - ✓ = Confirmar
   - ✕ = Cancelar

3. **Accesibilidad:**
   - Todos los elementos tienen etiquetas descriptivas
   - Botones con nombres claros
   - Mensajes de error/éxito informativos
   - Confirmaciones antes de acciones irreversibles
