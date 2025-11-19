#!/bin/bash

echo "=========================================="
echo "DEBUG: IMPORTACIÓN DE LOGS DE ZEEK"
echo "=========================================="
echo ""

cd /home/Security2
source .venv/bin/activate

python3 << 'EOF'
import sys
sys.path.insert(0, '.')

from database.db_manager import DatabaseManager
from modules.zeek_analyzer import ZeekAnalyzer
import os

print("=== 1. VERIFICANDO RUTAS DE LOGS ===")

# Posibles rutas de logs
log_paths = [
    '/opt/zeek/logs/current',
    '/opt/zeek/spool/zeek',
    '/usr/local/zeek/logs/current',
    '/var/log/zeek/current'
]

log_dir = None
for path in log_paths:
    if os.path.exists(path):
        print(f"✓ Encontrado: {path}")
        # Si es un symlink, obtener el destino real
        if os.path.islink(path):
            real_path = os.readlink(path)
            print(f"  → Es un symlink a: {real_path}")
            if not real_path.startswith('/'):
                # Ruta relativa
                real_path = os.path.join(os.path.dirname(path), real_path)
            log_dir = real_path
        else:
            log_dir = path
        break
    else:
        print(f"✗ No existe: {path}")

if not log_dir:
    print("\n❌ NO SE ENCONTRÓ DIRECTORIO DE LOGS")
    exit(1)

print(f"\n✓ Usando directorio: {log_dir}")
print("")

# Verificar archivos en el directorio
print("=== 2. ARCHIVOS EN EL DIRECTORIO ===")
if os.path.exists(log_dir):
    files = os.listdir(log_dir)
    print(f"Total de archivos: {len(files)}")

    log_files = ['conn.log', 'dns.log', 'http.log', 'ssl.log', 'files.log', 'notice.log']

    for log_file in log_files:
        full_path = os.path.join(log_dir, log_file)
        if os.path.exists(full_path):
            size = os.path.getsize(full_path)
            print(f"  ✓ {log_file} ({size} bytes)")

            # Verificar permisos de lectura
            if os.access(full_path, os.R_OK):
                print(f"    → Permisos de lectura: OK")

                # Leer primeras 3 líneas
                try:
                    with open(full_path, 'r') as f:
                        lines = []
                        for i, line in enumerate(f):
                            if i >= 3:
                                break
                            line = line.strip()
                            if line and not line.startswith('#'):
                                lines.append(line[:80] + '...' if len(line) > 80 else line)

                        if lines:
                            print(f"    → Primeras líneas de datos:")
                            for line in lines:
                                print(f"      {line}")
                        else:
                            print(f"    → Solo tiene comentarios o está vacío")
                except Exception as e:
                    print(f"    ✗ Error leyendo archivo: {e}")
            else:
                print(f"    ✗ NO tiene permisos de lectura")
        else:
            print(f"  ✗ {log_file} NO EXISTE")
    print("")
else:
    print(f"✗ El directorio {log_dir} no existe\n")
    exit(1)

# Probar importación con debug
print("=== 3. PROBANDO IMPORTACIÓN ===")

db = DatabaseManager()
analyzer = ZeekAnalyzer(db)

# Verificar qué método se está usando
print(f"ZeekAnalyzer inicializado")
print(f"DB Manager: {db}")

# Obtener lista de archivos de log
log_files_result = analyzer.zeek_manager.get_log_files()
print(f"\nArchivos de log detectados por ZeekManager:")
print(f"  {log_files_result}")

# Intentar importar conn.log específicamente
print("\n=== 4. IMPORTANDO CONN.LOG (DEBUG) ===")

from modules.zeek_analyzer import ZeekLogParser

conn_log_path = os.path.join(log_dir, 'conn.log')
if os.path.exists(conn_log_path):
    print(f"Parseando: {conn_log_path}")
    events = ZeekLogParser.parse_conn_log(conn_log_path, limit=5)
    print(f"Eventos parseados: {len(events)}")

    if events:
        print("\nPrimer evento:")
        import json
        print(json.dumps(events[0], indent=2))
    else:
        print("⚠️  No se parsearon eventos")

        # Leer el archivo directamente
        print("\nContenido directo del archivo (primeras 10 líneas):")
        with open(conn_log_path, 'r') as f:
            for i, line in enumerate(f):
                if i >= 10:
                    break
                print(f"  {i+1}: {line.rstrip()[:120]}")
else:
    print(f"✗ {conn_log_path} no existe")

print("")

# Intentar importación completa
print("=== 5. IMPORTACIÓN COMPLETA ===")
result = analyzer.import_zeek_logs_to_db(log_type='all', limit=10)
print(f"Resultado: {result}")

EOF

echo ""
echo "=========================================="
echo "FIN DEL DEBUG"
echo "=========================================="
