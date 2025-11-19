#!/bin/bash

echo "=========================================="
echo "DIAGNÓSTICO DE ZEEK - ESTADO Y LOGS"
echo "=========================================="
echo ""

# 1. Estado del servicio Zeek
echo "1. ESTADO DEL SERVICIO ZEEK"
echo "-----------------------------------"
if [ -f /opt/zeek/bin/zeekctl ]; then
    sudo /opt/zeek/bin/zeekctl status
else
    echo "zeekctl no encontrado"
fi
echo ""

# 2. Verificar procesos Zeek
echo "2. PROCESOS ZEEK CORRIENDO"
echo "-----------------------------------"
ps aux | grep -E '[z]eek|[z]eekctl' || echo "No hay procesos Zeek corriendo"
echo ""

# 3. Verificar archivos de log
echo "3. ARCHIVOS DE LOG DE ZEEK"
echo "-----------------------------------"
ZEEK_LOG_DIRS=(
    "/opt/zeek/logs/current"
    "/opt/zeek/spool/zeek"
    "/var/log/zeek/current"
    "/usr/local/zeek/logs/current"
)

LOG_DIR=""
for dir in "${ZEEK_LOG_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        LOG_DIR="$dir"
        echo "✓ Directorio de logs encontrado: $dir"
        echo ""
        echo "Archivos en $dir:"
        ls -lh "$dir" 2>/dev/null
        break
    fi
done

if [ -z "$LOG_DIR" ]; then
    echo "✗ No se encontró directorio de logs de Zeek"
fi
echo ""

# 4. Verificar contenido de logs importantes
echo "4. CONTENIDO DE LOGS (últimas 5 líneas)"
echo "-----------------------------------"
if [ -n "$LOG_DIR" ]; then
    for log_file in conn.log dns.log http.log ssl.log; do
        if [ -f "$LOG_DIR/$log_file" ]; then
            echo ">>> $log_file (últimas 5 líneas):"
            tail -5 "$LOG_DIR/$log_file" 2>/dev/null || echo "Error leyendo $log_file"
            echo ""
        else
            echo "✗ $log_file no existe"
        fi
    done
else
    echo "No hay directorio de logs para revisar"
fi
echo ""

# 5. Verificar configuración de node.cfg
echo "5. CONFIGURACIÓN DE ZEEK (node.cfg)"
echo "-----------------------------------"
if [ -f /opt/zeek/etc/node.cfg ]; then
    cat /opt/zeek/etc/node.cfg
else
    echo "node.cfg no encontrado"
fi
echo ""

# 6. Verificar interfaces de red
echo "6. INTERFACES DE RED ACTIVAS"
echo "-----------------------------------"
ip addr show | grep -E '^[0-9]+:|inet ' | grep -v '127.0.0.1'
echo ""

# 7. Verificar permisos de captura
echo "7. PERMISOS DE CAPTURA (eth0)"
echo "-----------------------------------"
if [ -d /sys/class/net/eth0 ]; then
    echo "✓ Interfaz eth0 existe"
    echo "Estado: $(cat /sys/class/net/eth0/operstate 2>/dev/null || echo 'unknown')"
else
    echo "✗ Interfaz eth0 no existe"
    echo "Interfaces disponibles:"
    ls /sys/class/net/
fi
echo ""

# 8. Verificar base de datos
echo "8. REGISTROS EN LA BASE DE DATOS"
echo "-----------------------------------"
cd /home/Security2
source .venv/bin/activate 2>/dev/null

python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
try:
    from database.db_manager import DatabaseManager
    from database.models import ZeekConnection, ZeekDNS, ZeekHTTP, ZeekSSL

    db = DatabaseManager()
    session = db.get_session()

    conn_count = session.query(ZeekConnection).count()
    dns_count = session.query(ZeekDNS).count()
    http_count = session.query(ZeekHTTP).count()
    ssl_count = session.query(ZeekSSL).count()

    print(f"Conexiones en BD: {conn_count}")
    print(f"DNS en BD: {dns_count}")
    print(f"HTTP en BD: {http_count}")
    print(f"SSL en BD: {ssl_count}")

    if conn_count > 0:
        print("\nÚltimas 3 conexiones:")
        for conn in session.query(ZeekConnection).order_by(ZeekConnection.timestamp.desc()).limit(3):
            print(f"  {conn.timestamp} | {conn.source_ip}:{conn.source_port} -> {conn.dest_ip}:{conn.dest_port}")

    session.close()

except Exception as e:
    print(f"Error consultando BD: {e}")
    import traceback
    traceback.print_exc()
PYEOF

echo ""
echo "=========================================="
echo "FIN DEL DIAGNÓSTICO"
echo "=========================================="
