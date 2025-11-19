# Comando Rápido: Importar Logs de Zeek Ahora

Mientras terminamos de implementar el sistema de tareas programadas, puedes importar los logs de Zeek manualmente con este comando:

## En el Servidor

```bash
cd /home/Security2
source .venv/bin/activate

python3 << 'EOF'
import sys
sys.path.insert(0, '.')

from database.db_manager import DatabaseManager
from modules.zeek_analyzer import import_zeek_logs

print("Importando logs de Zeek...")
result = import_zeek_logs(limit=1000)

print("\n=== RESULTADO ===")
print(f"Éxito: {result['success']}")
print(f"Mensaje: {result['message']}")
print(f"\nDetalle:")
print(f"  - Conexiones: {result['connections_imported']}")
print(f"  - DNS: {result['dns_imported']}")
print(f"  - HTTP: {result['http_imported']}")
print(f"  - SSL: {result['ssl_imported']}")
print(f"  - Files: {result['files_imported']}")
print(f"  - Notices: {result['notices_imported']}")
print(f"\nTotal importado: {result['records_created']} registros")

if result['errors']:
    print(f"\nErrores: {result['errors']}")
EOF
```

## ¿Qué hace esto?

1. Importa hasta 1000 registros de cada tipo de log de Zeek:
   - `conn.log` → Conexiones de red
   - `dns.log` → Consultas DNS
   - `http.log` → Tráfico HTTP
   - `ssl.log` → Conexiones SSL/TLS
   - `files.log` → Archivos transferidos
   - `notice.log` → Alertas de Zeek

2. Los guarda en la base de datos

3. Los puedes ver inmediatamente en el panel web:
   - **Network Monitor** → **Zeek Dashboard**
   - **Network Monitor** → **Logs de Zeek**
   - **Network Monitor** → **Detecciones**

## Para Automatizar (Cron Manual)

Si quieres que se ejecute cada 5 minutos mientras terminamos el sistema de tareas:

```bash
# Crear script
cat > /home/Security2/cron_import_zeek.sh << 'EOF'
#!/bin/bash
cd /home/Security2
source .venv/bin/activate
python3 -c "import sys; sys.path.insert(0, '.'); from modules.zeek_analyzer import import_zeek_logs; import_zeek_logs(limit=1000)" >> /home/Security2/zeek_cron.log 2>&1
EOF

# Dar permisos
chmod +x /home/Security2/cron_import_zeek.sh

# Agregar a crontab (cada 5 minutos)
(crontab -l 2>/dev/null; echo "*/5 * * * * /home/Security2/cron_import_zeek.sh") | crontab -

# Verificar
crontab -l
```

## Ver Logs del Cron

```bash
tail -f /home/Security2/zeek_cron.log
```

## Eliminar el Cron (cuando tengamos el sistema web listo)

```bash
crontab -l | grep -v 'cron_import_zeek.sh' | crontab -
```

---

**Ejecuta el primer comando ahora** y luego recarga la página del dashboard de Zeek. Deberías ver datos inmediatamente. 📊
