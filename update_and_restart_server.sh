#!/bin/bash

echo "========================================"
echo "ACTUALIZACIÓN Y REINICIO DEL SERVIDOR"
echo "========================================"
echo ""

cd /home/Security2

# 1. Detener servidor Flask
echo "1. Deteniendo servidor Flask..."
FLASK_PID=$(ps aux | grep '[p]ython.*app.py' | awk '{print $2}')
if [ -n "$FLASK_PID" ]; then
    echo "   Matando proceso Flask (PID: $FLASK_PID)"
    sudo kill -9 $FLASK_PID
    sleep 2
    echo "   ✓ Servidor detenido"
else
    echo "   - No había servidor corriendo"
fi
echo ""

# 2. Actualizar código desde Git
echo "2. Actualizando código desde GitHub..."
git fetch origin
git reset --hard origin/main
echo "   ✓ Código actualizado"
echo ""

# 3. Verificar que Zeek esté instalado
echo "3. Verificando instalación de Zeek..."
if [ -f /opt/zeek/bin/zeek ]; then
    ZEEK_VERSION=$(/opt/zeek/bin/zeek --version)
    echo "   ✓ $ZEEK_VERSION"
else
    echo "   ✗ Zeek NO instalado"
fi
echo ""

# 4. Verificar módulos Python de Zeek
echo "4. Verificando módulos Python de Zeek..."
if [ -f modules/zeek_manager.py ]; then
    echo "   ✓ modules/zeek_manager.py"
fi
if [ -f modules/zeek_analyzer.py ]; then
    echo "   ✓ modules/zeek_analyzer.py"
fi
if [ -f modules/zeek_detections.py ]; then
    echo "   ✓ modules/zeek_detections.py"
fi
if [ -f routes/zeek_routes.py ]; then
    echo "   ✓ routes/zeek_routes.py"
fi
echo ""

# 5. Activar entorno virtual
echo "5. Activando entorno virtual..."
source .venv/bin/activate
echo "   ✓ Entorno virtual activado"
echo ""

# 6. Test rápido de importación
echo "6. Probando importación de módulos Zeek..."
python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
try:
    from modules.zeek_manager import ZeekManager
    from database.db_manager import DatabaseManager
    db = DatabaseManager()
    zm = ZeekManager(db)
    print(f"   ✓ ZeekManager importado")
    print(f"   - Zeek binary: {zm.zeek_binary}")
    print(f"   - Zeekctl binary: {zm.zeekctl_binary}")
    status = zm.check_zeek_installed()
    print(f"   - Instalado: {status['installed']}")
    print(f"   - Versión: {status.get('version', 'N/A')}")
    print(f"   - zeekctl disponible: {status['zeekctl_available']}")
except Exception as e:
    print(f"   ✗ ERROR: {e}")
    import traceback
    traceback.print_exc()
PYEOF
echo ""

# 7. Iniciar servidor Flask
echo "7. Iniciando servidor Flask..."
nohup python app.py > flask_server.log 2>&1 &
NEW_PID=$!
echo "   ✓ Servidor iniciado (PID: $NEW_PID)"
sleep 3
echo ""

# 8. Verificar que esté corriendo
echo "8. Verificando servidor..."
if ps -p $NEW_PID > /dev/null; then
    echo "   ✓ Servidor Flask corriendo correctamente"
    echo ""
    echo "========================================"
    echo "ACTUALIZACIÓN COMPLETADA CON ÉXITO"
    echo "========================================"
    echo ""
    echo "Puedes acceder al panel web en: http://195.26.243.120:5000"
    echo "Ve a la sección 'Network Monitor' > 'Zeek Dashboard'"
    echo ""
    echo "Logs del servidor: tail -f /home/Security2/flask_server.log"
else
    echo "   ✗ ERROR: El servidor no está corriendo"
    echo ""
    echo "Ver logs de error:"
    echo "  tail -20 /home/Security2/flask_server.log"
fi
