#!/bin/bash

echo "=========================================="
echo "VERIFICANDO BASE DE DATOS - LOGS DE ZEEK"
echo "=========================================="
echo ""

cd /home/Security2
source .venv/bin/activate

python3 << 'EOF'
import sys
sys.path.insert(0, '.')

from database.db_manager import DatabaseManager
from database.models import ZeekConnection, ZeekDNS, ZeekHTTP, ZeekSSL

try:
    db = DatabaseManager()
    session = db.get_session()

    # Contar registros
    conn_count = session.query(ZeekConnection).count()
    dns_count = session.query(ZeekDNS).count()
    http_count = session.query(ZeekHTTP).count()
    ssl_count = session.query(ZeekSSL).count()

    print("=== REGISTROS EN LA BASE DE DATOS ===")
    print(f"Conexiones (ZeekConnection): {conn_count}")
    print(f"DNS (ZeekDNS): {dns_count}")
    print(f"HTTP (ZeekHTTP): {http_count}")
    print(f"SSL (ZeekSSL): {ssl_count}")
    print("")

    if conn_count == 0 and dns_count == 0 and http_count == 0 and ssl_count == 0:
        print("❌ NO HAY DATOS EN LA BASE DE DATOS")
        print("")
        print("Esto significa que:")
        print("  1. No se han importado los logs todavía")
        print("  2. O hubo un error durante la importación")
        print("")
        print("Solución: Ejecuta el comando de importación:")
        print("  python3 -c \"import sys; sys.path.insert(0, '.'); from modules.zeek_analyzer import import_zeek_logs; print(import_zeek_logs(limit=1000))\"")
    else:
        print("✅ HAY DATOS EN LA BASE DE DATOS")
        print("")

        if conn_count > 0:
            print("=== ÚLTIMAS 5 CONEXIONES ===")
            for conn in session.query(ZeekConnection).order_by(ZeekConnection.timestamp.desc()).limit(5):
                print(f"  {conn.timestamp} | {conn.source_ip}:{conn.source_port} -> {conn.dest_ip}:{conn.dest_port} | {conn.protocol}")
            print("")

        if dns_count > 0:
            print("=== ÚLTIMAS 5 CONSULTAS DNS ===")
            for dns in session.query(ZeekDNS).order_by(ZeekDNS.timestamp.desc()).limit(5):
                print(f"  {dns.timestamp} | {dns.query} | {dns.source_ip}")
            print("")

        if http_count > 0:
            print("=== ÚLTIMAS 5 PETICIONES HTTP ===")
            for http in session.query(ZeekHTTP).order_by(ZeekHTTP.timestamp.desc()).limit(5):
                print(f"  {http.timestamp} | {http.method} {http.host}{http.uri}")
            print("")

    session.close()

except Exception as e:
    print(f"❌ ERROR: {e}")
    import traceback
    traceback.print_exc()

print("")
print("=== VERIFICANDO TABLA DE MODELOS ===")

# Verificar que las tablas existan
from database.models import Base
from sqlalchemy import inspect

db = DatabaseManager()
engine = db.engine
inspector = inspect(engine)

tables_needed = ['zeek_connections', 'zeek_dns', 'zeek_http', 'zeek_ssl', 'zeek_files', 'zeek_notices']
tables_exist = inspector.get_table_names()

print(f"Tablas en la BD: {len(tables_exist)}")

for table in tables_needed:
    if table in tables_exist:
        print(f"  ✓ {table}")
    else:
        print(f"  ✗ {table} NO EXISTE")

if not all(table in tables_exist for table in tables_needed):
    print("")
    print("⚠️  FALTAN TABLAS EN LA BASE DE DATOS")
    print("Solución: Ejecuta db.create_tables() para crearlas")

EOF

echo ""
echo "=========================================="
echo "FIN DE LA VERIFICACIÓN"
echo "=========================================="
