# Instrucciones - Sistema de Backup de Base de Datos

## Descripción

Sistema completo para exportar e importar la base de datos SQLite entre diferentes ambientes (servidor Ubuntu → desarrollo Windows).

## Características Implementadas

### 1. Exportar Base de Datos
- Crear archivo ZIP con la base de datos completa
- Incluye metadata (fecha, tablas, registros)
- Descarga directa desde el navegador
- Almacena backups en carpeta `backups/`

### 2. Importar Base de Datos
- Subir archivo ZIP de backup
- Validación del archivo
- Backup automático de la BD actual antes de importar
- Restauración completa de datos

### 3. Gestión de Backups
- Lista de todos los backups disponibles
- Información detallada de cada backup
- Descargar backups antiguos
- Eliminar backups no necesarios

### 4. Estadísticas
- Número de tablas en la base de datos
- Total de registros
- Información por tabla

## Cómo Usar

### Paso 1: Exportar desde el Servidor Ubuntu

1. Accede al servidor Ubuntu donde está corriendo la aplicación
2. Ve al menú **Sistema → Base de Datos** (o directamente a `/database/config`)
3. En la sección **Exportar Base de Datos**, haz clic en **Descargar Base de Datos**
4. Se creará un archivo ZIP y aparecerá un enlace de descarga
5. Haz clic en **Descargar Archivo** para obtener el ZIP

**Ejemplo de archivo generado:**
```
security_db_backup_20251120_040000.zip
  ├── security.db           (base de datos SQLite)
  └── metadata.json         (información del backup)
```

### Paso 2: Importar en Desarrollo Windows

1. Copia el archivo ZIP descargado a tu máquina Windows
2. Accede a tu aplicación local en desarrollo
3. Ve al menú **Sistema → Base de Datos**
4. En la sección **Importar Base de Datos**:
   - Marca la opción "Crear backup de la base de datos actual antes de importar" (recomendado)
   - Haz clic en **Seleccionar archivo de backup**
   - Selecciona el archivo ZIP descargado
   - Haz clic en **Importar Base de Datos**
5. Confirma la acción en el diálogo de advertencia
6. Espera a que se complete la importación
7. Haz clic en **Recargar Página** cuando aparezca el mensaje de éxito

### Paso 3: Verificar la Importación

1. Revisa las estadísticas de la base de datos en la parte superior
2. Verifica que las métricas (tablas, registros) coincidan con las del servidor
3. Navega por el dashboard para confirmar que los datos están correctos

## Archivos Creados

### Backend
1. **`modules/database_backup.py`** (400+ líneas)
   - Clase `DatabaseBackup` para gestión de backups
   - Métodos: `export_database()`, `import_database()`, `list_backups()`, `delete_backup()`

2. **`routes/database_routes.py`** (300+ líneas)
   - Blueprint con endpoints REST
   - 7 endpoints: export, download, import, list, delete, stats, config page

### Frontend
3. **`templates/database_config.html`** (500+ líneas)
   - Interfaz web completa
   - Estadísticas de BD actual
   - Formulario de exportación
   - Formulario de importación con drag & drop
   - Tabla de backups disponibles

### Integración
4. **`app.py`** (modificado)
   - Inicialización de `DatabaseBackup`
   - Registro del blueprint `database`

5. **`templates/base.html`** (modificado)
   - Menú "Base de Datos" en sección Sistema

## API Endpoints

### POST /database/api/export
Exportar base de datos a ZIP
```json
Request:
{
  "include_metadata": true
}

Response:
{
  "success": true,
  "backup_file": "security_db_backup_20251120_040000.zip",
  "size_kb": 1234.56,
  "tables_count": 30,
  "total_records": 5000,
  "download_url": "/database/api/download/security_db_backup_20251120_040000.zip"
}
```

### GET /database/api/download/<filename>
Descargar archivo de backup
- Devuelve archivo ZIP para descarga

### POST /database/api/import
Importar base de datos desde ZIP
```
Request: Multipart form data
  - backup_file: archivo ZIP
  - backup_current: true/false (query param)

Response:
{
  "success": true,
  "message": "Base de datos importada exitosamente",
  "tables_count": 30,
  "total_records": 5000,
  "backup_file": "security_db_backup_20251120_040500.zip"
}
```

### GET /database/api/backups
Listar todos los backups disponibles
```json
Response:
{
  "success": true,
  "backups": [
    {
      "filename": "security_db_backup_20251120_040000.zip",
      "size_kb": 1234.56,
      "created_at": "2025-11-20T04:00:00",
      "tables_count": 30,
      "total_records": 5000,
      "download_url": "/database/api/download/..."
    }
  ],
  "count": 1
}
```

### DELETE /database/api/backups/<filename>
Eliminar un backup específico

### GET /database/api/stats
Obtener estadísticas de la BD actual
```json
Response:
{
  "success": true,
  "stats": {
    "tables_count": 30,
    "total_records": 5000,
    "tables": [
      {"name": "security_events", "records": 1000},
      {"name": "blocked_ips", "records": 150},
      ...
    ]
  }
}
```

## Estructura de Metadata

El archivo `metadata.json` dentro del ZIP contiene:
```json
{
  "export_date": "2025-11-20T04:00:00",
  "db_file": "database/security.db",
  "tables_count": 30,
  "total_records": 5000,
  "tables": [
    {"name": "security_events", "records": 1000},
    {"name": "blocked_ips", "records": 150},
    ...
  ],
  "version": "1.0.0",
  "system": "Security Monitor"
}
```

## Notas de Seguridad

### Validaciones Implementadas
1. **Validación de nombres de archivo** - Solo archivos con formato `security_db_backup_*.zip`
2. **Extensión de archivo** - Solo archivos `.zip` permitidos
3. **Backup automático** - Crea backup antes de importar (por defecto)
4. **Confirmación de usuario** - Diálogo de confirmación antes de importar

### Advertencias
⚠️ **IMPORTANTE:**
- La importación **reemplaza completamente** la base de datos actual
- Siempre se crea un backup automático antes de importar (a menos que se desactive)
- Los backups se almacenan en `backups/` - asegúrate de tener espacio en disco
- El archivo ZIP debe contener `security.db` válido

## Troubleshooting

### Error: "Base de datos no encontrada"
- Verifica que el archivo `database/security.db` existe
- Ejecuta las migraciones necesarias primero

### Error: "El archivo ZIP no contiene security.db"
- Asegúrate de que el ZIP fue creado por este sistema
- Verifica que el archivo no esté corrupto

### Error: Permisos denegados
- En Windows: Ejecuta como administrador si es necesario
- En Linux: Verifica permisos del directorio `database/` y `backups/`

### La importación falla
- Verifica que hay espacio en disco suficiente
- Revisa que la base de datos no esté siendo usada por otro proceso
- Consulta los logs del servidor para más detalles

## Flujo de Trabajo Recomendado

### Desarrollo → Producción
1. Desarrolla y prueba en ambiente local (Windows)
2. Cuando esté listo, exporta tu BD local
3. Importa en el servidor de staging/testing
4. Prueba exhaustivamente
5. Exporta del staging
6. Importa en producción

### Producción → Desarrollo
1. Exporta BD desde servidor de producción (Ubuntu)
2. Descarga el archivo ZIP
3. Importa en tu ambiente local (Windows)
4. Ahora tienes datos reales para desarrollar/debuggear

### Backups Regulares
1. Crea backups automáticos usando tareas programadas
2. Descarga backups periódicamente a tu máquina local
3. Guarda copias en almacenamiento externo/cloud
4. Prueba la restauración regularmente

## Líneas de Código

- **Backend:** ~700 líneas
- **Frontend:** ~500 líneas
- **Total:** ~1200 líneas

## Última Actualización

**Fecha:** 2025-11-20
**Versión:** 1.0.0
**Estado:** Completado ✓
