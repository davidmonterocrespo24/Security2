#!/bin/bash

echo "=========================================="
echo "DIAGNÓSTICO DEL SISTEMA ZEEK"
echo "=========================================="
echo ""

# 1. Verificar Zeek instalado
echo "1. VERIFICANDO INSTALACIÓN DE ZEEK"
echo "-----------------------------------"
if [ -f /opt/zeek/bin/zeek ]; then
    echo "✓ Zeek instalado en /opt/zeek/bin/zeek"
    /opt/zeek/bin/zeek --version
else
    echo "✗ Zeek NO encontrado en /opt/zeek/bin/"
fi

if [ -f /opt/zeek/bin/zeekctl ]; then
    echo "✓ zeekctl disponible en /opt/zeek/bin/zeekctl"
else
    echo "✗ zeekctl NO encontrado"
fi
echo ""

# 2. Verificar estado del servicio
echo "2. ESTADO DEL SERVICIO ZEEK"
echo "-----------------------------------"
if [ -f /opt/zeek/bin/zeekctl ]; then
    sudo /opt/zeek/bin/zeekctl status
else
    echo "zeekctl no disponible"
fi
echo ""

# 3. Verificar módulos Python
echo "3. VERIFICANDO MÓDULOS PYTHON"
echo "-----------------------------------"
cd /home/Security2
if [ -f modules/zeek_manager.py ]; then
    echo "✓ modules/zeek_manager.py existe"
    ls -lh modules/zeek_manager.py
else
    echo "✗ modules/zeek_manager.py NO existe"
fi

if [ -f modules/zeek_analyzer.py ]; then
    echo "✓ modules/zeek_analyzer.py existe"
    ls -lh modules/zeek_analyzer.py
else
    echo "✗ modules/zeek_analyzer.py NO existe"
fi

if [ -f modules/zeek_detections.py ]; then
    echo "✓ modules/zeek_detections.py existe"
    ls -lh modules/zeek_detections.py
else
    echo "✗ modules/zeek_detections.py NO existe"
fi
echo ""

# 4. Verificar rutas
echo "4. VERIFICANDO RUTAS FLASK"
echo "-----------------------------------"
if [ -f routes/zeek_routes.py ]; then
    echo "✓ routes/zeek_routes.py existe"
    ls -lh routes/zeek_routes.py
else
    echo "✗ routes/zeek_routes.py NO existe"
fi
echo ""

# 5. Verificar templates
echo "5. VERIFICANDO TEMPLATES HTML"
echo "-----------------------------------"
for template in zeek_dashboard.html zeek_install.html zeek_config.html zeek_logs.html zeek_detections.html; do
    if [ -f templates/$template ]; then
        echo "✓ templates/$template existe"
    else
        echo "✗ templates/$template NO existe"
    fi
done
echo ""

# 6. Verificar app.py
echo "6. VERIFICANDO INTEGRACIÓN EN APP.PY"
echo "-----------------------------------"
if grep -q "zeek_manager" app.py; then
    echo "✓ zeek_manager importado en app.py"
else
    echo "✗ zeek_manager NO importado en app.py"
fi

if grep -q "zeek_blueprint" app.py; then
    echo "✓ zeek_blueprint registrado en app.py"
else
    echo "✗ zeek_blueprint NO registrado en app.py"
fi
echo ""

# 7. Verificar proceso Flask
echo "7. ESTADO DEL SERVIDOR FLASK"
echo "-----------------------------------"
FLASK_PID=$(ps aux | grep '[p]ython.*app.py' | awk '{print $2}')
if [ -n "$FLASK_PID" ]; then
    echo "✓ Servidor Flask corriendo (PID: $FLASK_PID)"
    ps aux | grep '[p]ython.*app.py'
else
    echo "✗ Servidor Flask NO está corriendo"
fi
echo ""

# 8. Verificar interfaces de red
echo "8. INTERFACES DE RED DISPONIBLES"
echo "-----------------------------------"
ip link show | grep -E '^[0-9]+: (eth|ens|enp)' | awk '{print $2}' | sed 's/:$//'
echo ""

# 9. Verificar logs de Flask
echo "9. ÚLTIMAS LÍNEAS DE LOGS DE FLASK"
echo "-----------------------------------"
if [ -f flask_server.log ]; then
    echo "Últimas 20 líneas de flask_server.log:"
    tail -20 flask_server.log
else
    echo "No se encontró flask_server.log"
fi
echo ""

# 10. Test de importación Python
echo "10. TEST DE IMPORTACIÓN DE MÓDULOS ZEEK"
echo "-----------------------------------"
cd /home/Security2
if [ -d .venv ]; then
    source .venv/bin/activate
fi

python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')

try:
    from modules.zeek_manager import ZeekManager
    print("✓ ZeekManager importado correctamente")

    from database.db_manager import DatabaseManager
    db = DatabaseManager()
    zm = ZeekManager(db)

    print(f"  - Zeek binary: {zm.zeek_binary}")
    print(f"  - Zeekctl binary: {zm.zeekctl_binary}")

    status = zm.check_zeek_installed()
    print(f"  - Instalado: {status['installed']}")
    print(f"  - Versión: {status.get('version', 'N/A')}")
    print(f"  - zeekctl disponible: {status['zeekctl_available']}")

except Exception as e:
    print(f"✗ Error importando módulos: {e}")
    import traceback
    traceback.print_exc()
PYEOF

echo ""
echo "=========================================="
echo "FIN DEL DIAGNÓSTICO"
echo "=========================================="
