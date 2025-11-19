# Instrucciones para Actualizar el Servidor y Activar Zeek

## Resumen del Problema

Tu sistema tiene Zeek instalado correctamente en `/opt/zeek/bin/`, pero el panel web no lo detectaba porque:

1. **El código actualizado no estaba en el servidor** - Los cambios con sudo y detección de interfaces estaban solo en Windows
2. **El servidor Flask necesita reiniciarse** - Para que detecte los binarios de Zeek en `/opt/zeek/bin/`
3. **Faltaba usar sudo** - Los comandos de zeekctl necesitan permisos de root

## Solución Automática (Recomendada)

### Paso 1: Conectarte al servidor

```bash
ssh root@195.26.243.120
# Contraseña: FywpDmtd8qwrq6jGi2o70EuCaX10
```

### Paso 2: Ir al directorio del proyecto

```bash
cd /home/Security2
```

### Paso 3: Descargar y ejecutar el script de actualización

```bash
# Descargar los cambios del repositorio
git pull

# Dar permisos de ejecución al script
chmod +x update_and_restart_server.sh

# Ejecutar el script
./update_and_restart_server.sh
```

Este script hace todo automáticamente:
- ✅ Detiene el servidor Flask actual
- ✅ Actualiza el código desde GitHub
- ✅ Verifica que Zeek esté instalado
- ✅ Prueba la importación de módulos
- ✅ Reinicia el servidor Flask
- ✅ Verifica que todo funcione

### Paso 4: Verificar que funciona

1. Abre tu navegador
2. Ve a: `http://195.26.243.120:5000`
3. Inicia sesión
4. Ve a **Network Monitor** → **Zeek Dashboard**
5. Deberías ver que Zeek está detectado con versión 7.0.11

---

## Solución Manual (Si prefieres hacerlo paso a paso)

### 1. Conectarte al servidor

```bash
ssh root@195.26.243.120
cd /home/Security2
```

### 2. Detener el servidor Flask

```bash
# Encontrar el proceso
ps aux | grep 'python.*app.py'

# Matarlo (reemplaza XXXX con el PID que viste)
sudo kill -9 XXXX
```

### 3. Actualizar el código

```bash
git pull origin main
```

### 4. Verificar archivos

```bash
# Verificar que existan los módulos de Zeek
ls -lh modules/zeek*.py
ls -lh routes/zeek_routes.py
ls -lh templates/zeek*.html

# Deberías ver:
# modules/zeek_manager.py
# modules/zeek_analyzer.py
# modules/zeek_detections.py
# routes/zeek_routes.py
# templates/zeek_dashboard.html
# templates/zeek_install.html
# templates/zeek_config.html
# templates/zeek_logs.html
# templates/zeek_detections.html
```

### 5. Probar la detección de Zeek

```bash
# Activar entorno virtual
source .venv/bin/activate

# Probar importación
python3 << 'EOF'
import sys
sys.path.insert(0, '.')
from modules.zeek_manager import ZeekManager
from database.db_manager import DatabaseManager

db = DatabaseManager()
zm = ZeekManager(db)

print(f"Zeek binary: {zm.zeek_binary}")
print(f"Zeekctl binary: {zm.zeekctl_binary}")

status = zm.check_zeek_installed()
print(f"Instalado: {status['installed']}")
print(f"Versión: {status.get('version')}")
print(f"zeekctl disponible: {status['zeekctl_available']}")

# Probar detección de interfaces
interfaces = zm.get_interfaces()
print(f"Interfaces detectadas: {interfaces}")

default_iface = zm.get_default_interface()
print(f"Interfaz por defecto: {default_iface}")
EOF
```

**Resultado esperado:**
```
Zeek binary: /opt/zeek/bin/zeek
Zeekctl binary: /opt/zeek/bin/zeekctl
Instalado: True
Versión: zeek version 7.0.11
zeekctl disponible: True
Interfaces detectadas: [{'name': 'eth0', 'ip': '195.26.243.120', 'status': 'UP'}]
Interfaz por defecto: eth0
```

### 6. Reiniciar el servidor Flask

```bash
# Asegurarte de estar en el directorio correcto
cd /home/Security2

# Activar entorno virtual si no está activado
source .venv/bin/activate

# Iniciar en background
nohup python app.py > flask_server.log 2>&1 &

# Ver el PID del nuevo proceso
echo $!

# Esperar 3 segundos
sleep 3

# Verificar que esté corriendo
ps aux | grep '[p]ython.*app.py'
```

### 7. Ver los logs

```bash
# Ver los últimos logs
tail -f flask_server.log

# Presiona Ctrl+C para salir
```

### 8. Verificar en el navegador

1. Abre: `http://195.26.243.120:5000`
2. Inicia sesión
3. Ve a **Network Monitor** → **Zeek Dashboard**

---

## Iniciar Zeek desde el Panel Web

Una vez que el dashboard muestre que Zeek está instalado:

1. Ve a **Network Monitor** → **Config Zeek**
2. Selecciona la interfaz **eth0**
3. Haz clic en **Iniciar**
4. Espera unos segundos
5. Regresa al **Zeek Dashboard** y deberías ver que está corriendo

---

## Comando Todo-en-Uno

Si solo quieres copiar y pegar un comando:

```bash
ssh root@195.26.243.120 << 'ENDSSH'
cd /home/Security2
pkill -9 -f 'python.*app.py'
git pull origin main
source .venv/bin/activate
nohup python app.py > flask_server.log 2>&1 &
sleep 3
ps aux | grep '[p]ython.*app.py'
echo "✓ Servidor actualizado y reiniciado"
echo "Accede a: http://195.26.243.120:5000"
ENDSSH
```

---

## Solución de Problemas

### Si el servidor no inicia

```bash
# Ver errores en los logs
cat flask_server.log | tail -50

# Verificar que no haya otro proceso usando el puerto 5000
sudo netstat -tulpn | grep 5000

# Si hay otro proceso, matarlo:
sudo kill -9 $(sudo lsof -t -i:5000)
```

### Si Zeek no aparece instalado

```bash
# Verificar que Zeek esté realmente instalado
/opt/zeek/bin/zeek --version

# Si no está, instalarlo:
sudo apt-get update
sudo apt-get install -y zeek
```

### Si zeekctl no funciona

```bash
# Probar con sudo
sudo /opt/zeek/bin/zeekctl status

# Si funciona, entonces el problema es de permisos
# El código ya está actualizado para usar sudo
```

---

## Cambios Realizados en el Código

Los siguientes cambios se hicieron en `modules/zeek_manager.py`:

1. **Agregado sudo a comandos zeekctl:**
   - `sudo /opt/zeek/bin/zeekctl status`
   - `sudo /opt/zeek/bin/zeekctl deploy`
   - `sudo /opt/zeek/bin/zeekctl stop`

2. **Mejora en detección de interfaces:**
   - Filtra interfaces docker, veth, loopback
   - Auto-detecta eth0 como interfaz preferida
   - Usa `ip link show` para detección más robusta

3. **Auto-selección de interfaz:**
   - Si no se especifica interfaz, usa `get_default_interface()`
   - Prefiere eth0 > ethX > primera interfaz activa

4. **Escritura de archivos de configuración:**
   - Usa archivos temporales + sudo mv para node.cfg
   - Evita problemas de permisos

---

## Resumen

**Antes:**
- ❌ Zeek instalado pero no detectado
- ❌ zeekctl requería sudo
- ❌ Interfaz ens3 no existía (era eth0)

**Después:**
- ✅ Zeek detectado automáticamente
- ✅ Comandos usan sudo correctamente
- ✅ Interfaz eth0 auto-detectada
- ✅ Todo funciona desde el panel web

Una vez ejecutes el script de actualización, deberías poder usar Zeek completamente desde tu panel web.
