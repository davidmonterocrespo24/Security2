#!/bin/bash

echo "=========================================="
echo "IMPORTANDO LOGS DE ZEEK A LA BASE DE DATOS"
echo "=========================================="
echo ""

cd /home/Security2
source .venv/bin/activate

echo "Importando logs de Zeek..."
echo ""

python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')

from database.db_manager import DatabaseManager
from modules.zeek_analyzer import ZeekAnalyzer

print("Inicializando módulos...")
db = DatabaseManager()
analyzer = ZeekAnalyzer(db)

print("Importando logs de Zeek a la base de datos...")
print("Esto puede tomar 30-60 segundos dependiendo de la cantidad de logs...")
print("")

try:
    # Importar todos los logs (últimos 5000 registros de cada tipo)
    result = analyzer.import_zeek_logs_to_db(log_type='all', limit=5000)

    print("=" * 50)
    print("RESULTADO DE LA IMPORTACIÓN")
    print("=" * 50)
    print(f"✓ Conexiones importadas: {result.get('connections_imported', 0)}")
    print(f"✓ DNS importados: {result.get('dns_imported', 0)}")
    print(f"✓ HTTP importados: {result.get('http_imported', 0)}")
    print(f"✓ SSL importados: {result.get('ssl_imported', 0)}")
    print(f"✓ Files importados: {result.get('files_imported', 0)}")
    print(f"✓ Notices importados: {result.get('notices_imported', 0)}")
    print("")

    if result.get('success'):
        print("✅ IMPORTACIÓN COMPLETADA CON ÉXITO")
    else:
        print("⚠️  Importación completada con algunos errores")
        if 'errors' in result:
            print(f"Errores: {result['errors']}")

except Exception as e:
    print(f"❌ ERROR durante la importación: {e}")
    import traceback
    traceback.print_exc()

print("")
print("Verificando registros en la base de datos...")

try:
    from database.models import ZeekConnection, ZeekDNS, ZeekHTTP, ZeekSSL

    session = db.get_session()

    conn_count = session.query(ZeekConnection).count()
    dns_count = session.query(ZeekDNS).count()
    http_count = session.query(ZeekHTTP).count()
    ssl_count = session.query(ZeekSSL).count()

    print("=" * 50)
    print("REGISTROS EN LA BASE DE DATOS")
    print("=" * 50)
    print(f"Conexiones: {conn_count}")
    print(f"DNS: {dns_count}")
    print(f"HTTP: {http_count}")
    print(f"SSL: {ssl_count}")
    print("")

    if conn_count > 0:
        print("Últimas 5 conexiones importadas:")
        print("-" * 80)
        for conn in session.query(ZeekConnection).order_by(ZeekConnection.timestamp.desc()).limit(5):
            print(f"  {conn.timestamp} | {conn.source_ip}:{conn.source_port} -> {conn.dest_ip}:{conn.dest_port} | {conn.protocol}")
        print("")

    if dns_count > 0:
        print("Últimas 5 consultas DNS importadas:")
        print("-" * 80)
        for dns in session.query(ZeekDNS).order_by(ZeekDNS.timestamp.desc()).limit(5):
            print(f"  {dns.timestamp} | {dns.query} | {dns.source_ip}")
        print("")

    session.close()

except Exception as e:
    print(f"Error verificando BD: {e}")

PYEOF

echo ""
echo "=========================================="
echo "IMPORTACIÓN FINALIZADA"
echo "=========================================="
echo ""
echo "Ahora puedes ver los datos en el panel web:"
echo "  http://195.26.243.120:5000"
echo "  Network Monitor > Zeek Dashboard"
echo ""
