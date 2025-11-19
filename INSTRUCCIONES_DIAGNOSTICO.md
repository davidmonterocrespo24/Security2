# Instrucciones para Diagnosticar el Problema de Zeek

## Paso 1: Conectarte al servidor

```bash
ssh root@195.26.243.120
# Contraseña: FywpDmtd8qwrq6jGi2o70EuCaX10
```

## Paso 2: Ir al directorio del proyecto

```bash
cd /home/Security2
```

## Paso 3: Copiar el script de diagnóstico

Copia el contenido del archivo `diagnostic_zeek.sh` que está en tu Windows (E:\Python\Security2\diagnostic_zeek.sh) y créalo en el servidor:

```bash
nano diagnostic_zeek.sh
# Pega el contenido completo
# Ctrl+O para guardar, Enter, Ctrl+X para salir
```

## Paso 4: Dar permisos de ejecución

```bash
chmod +x diagnostic_zeek.sh
```

## Paso 5: Ejecutar el diagnóstico

```bash
./diagnostic_zeek.sh > diagnostico_resultado.txt 2>&1
```

## Paso 6: Ver el resultado

```bash
cat diagnostico_resultado.txt
```

## Paso 7: Copiar el resultado

Copia todo el contenido de `diagnostico_resultado.txt` y pégalo aquí para que pueda analizar qué falta.

---

## Alternativa: Si tienes Git configurado

Si tienes git configurado en el servidor, puedes hacer:

```bash
cd /home/Security2

# Ver qué archivos faltan comparado con el repo local
git status

# Si hay archivos sin subir, subirlos desde Windows:
# (Ejecutar en Windows, en E:\Python\Security2)
git add .
git commit -m "Add Zeek modules and templates"
git push

# Luego en el servidor:
git pull
```

---

## Comando Rápido Todo-en-Uno

Si prefieres ejecutar todo de una vez:

```bash
cd /home/Security2 && \
bash << 'EOF'
#!/bin/bash
echo "=== VERIFICANDO ZEEK ==="
/opt/zeek/bin/zeek --version 2>&1
echo ""
echo "=== ARCHIVOS DE MÓDULOS ==="
ls -lh modules/zeek*.py 2>&1
echo ""
echo "=== RUTAS ZEEK ==="
ls -lh routes/zeek_routes.py 2>&1
echo ""
echo "=== TEMPLATES ZEEK ==="
ls -lh templates/zeek*.html 2>&1
echo ""
echo "=== SERVIDOR FLASK ==="
ps aux | grep '[p]ython.*app.py'
echo ""
echo "=== TEST PYTHON ==="
source .venv/bin/activate
python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
try:
    from modules.zeek_manager import ZeekManager
    from database.db_manager import DatabaseManager
    db = DatabaseManager()
    zm = ZeekManager(db)
    print(f"Zeek binary: {zm.zeek_binary}")
    print(f"Zeekctl binary: {zm.zeekctl_binary}")
    status = zm.check_zeek_installed()
    print(f"Instalado: {status['installed']}")
    print(f"Versión: {status.get('version')}")
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
PYEOF
EOF
```

Copia y pega este comando completo en el servidor y envíame el resultado.
