# Solución: Zeek No Detectado en el Panel Web

## Problema Identificado

Tu servidor **SÍ tiene Zeek instalado** en `/opt/zeek/bin/`, pero el panel web no lo detectaba. Estos fueron los problemas:

### 1. **Código desactualizado en el servidor**
- Los archivos de Zeek (`zeek_manager.py`, `zeek_analyzer.py`, etc.) estaban en el repositorio
- Pero los últimos cambios (agregando `sudo` y mejorando detección de interfaces) solo estaban en tu Windows local
- El servidor no tenía estos cambios porque no se hizo `git pull`

### 2. **Falta de permisos sudo**
```bash
# ❌ No funcionaba (sin sudo):
/opt/zeek/bin/zeekctl status
# Error: zeekctl: command not found (cuando lo llamaba el usuario www-data del servidor Flask)

# ✅ Funciona (con sudo):
sudo /opt/zeek/bin/zeekctl status
```

### 3. **Interfaz de red incorrecta**
- El código buscaba `ens3` pero tu servidor tiene `eth0`
- Necesitaba auto-detección de la interfaz correcta

### 4. **Servidor Flask sin reiniciar**
- El servidor Flask estaba corriendo con código viejo
- No había reiniciado después de la instalación de Zeek
- No detectaba los binarios en `/opt/zeek/bin/`

---

## Solución Aplicada

### Cambios en el Código (ya en GitHub)

#### 1. Agregado sudo a todos los comandos de zeekctl
**Archivo:** `modules/zeek_manager.py`

```python
# Línea 324-330: Status con sudo
result = subprocess.run(
    ['sudo', self.zeekctl_binary, 'status'],  # ← Agregado 'sudo'
    capture_output=True,
    text=True,
    timeout=10
)

# Línea 390-396: Deploy con sudo
result = subprocess.run(
    ['sudo', self.zeekctl_binary, 'deploy'],  # ← Agregado 'sudo'
    capture_output=True,
    text=True,
    timeout=60
)

# Línea 436-442: Stop con sudo
result = subprocess.run(
    ['sudo', self.zeekctl_binary, 'stop'],  # ← Agregado 'sudo'
    capture_output=True,
    text=True,
    timeout=60
)
```

#### 2. Auto-detección de interfaz de red
**Archivo:** `modules/zeek_manager.py`

```python
# Línea 547-575: Nueva función get_default_interface()
def get_default_interface(self):
    """
    Obtener la interfaz de red principal (por defecto)

    Returns:
        str: Nombre de la interfaz (ej: eth0)
    """
    interfaces = self.get_interfaces()

    # Filtrar interfaces UP con IP
    active_interfaces = [
        iface for iface in interfaces
        if iface['status'] == 'UP' and iface['ip'] is not None
    ]

    # Preferir eth0, luego cualquier ethX, luego cualquier otra
    for iface in active_interfaces:
        if iface['name'] == 'eth0':
            return 'eth0'  # ← Tu servidor usa eth0

    for iface in active_interfaces:
        if iface['name'].startswith('eth'):
            return iface['name']

    # Si no hay eth, devolver la primera activa
    if active_interfaces:
        return active_interfaces[0]['name']

    return None
```

#### 3. Mejora en get_interfaces() para filtrar docker/veth
**Archivo:** `modules/zeek_manager.py` (Línea 483-545)

```python
# Filtrar interfaces especiales
if iface_name in ['lo', 'docker0'] or iface_name.startswith('br-') or iface_name.startswith('veth'):
    continue  # ← Ignora lo, docker0, br-*, veth*
```

#### 4. Auto-selección de interfaz al iniciar Zeek
**Archivo:** `modules/zeek_manager.py` (Línea 382-388)

```python
# Si no se proporciona interfaz, usar la interfaz por defecto
if not interface:
    interface = self.get_default_interface()  # ← Auto-detecta eth0

# Si se proporciona interfaz, configurarla
if interface:
    self.configure_zeek(interface=interface)
```

#### 5. Escritura de node.cfg con sudo
**Archivo:** `modules/zeek_manager.py` (Línea 633-644)

```python
# Escribir archivo usando sudo (requiere permisos)
# Crear archivo temporal
temp_file = '/tmp/node.cfg.tmp'
with open(temp_file, 'w') as f:
    f.writelines(new_lines)

# Mover con sudo
subprocess.run(
    ['sudo', 'mv', temp_file, cfg_path],  # ← Usa sudo para mover
    capture_output=True,
    timeout=10
)
```

---

## Cómo Actualizar el Servidor

### Opción 1: Script Automático (Recomendado) ⚡

```bash
# 1. Conectarte al servidor
ssh root@195.26.243.120
# Contraseña: FywpDmtd8qwrq6jGi2o70EuCaX10

# 2. Ir al directorio
cd /home/Security2

# 3. Actualizar repositorio
git pull

# 4. Ejecutar script de actualización
chmod +x update_and_restart_server.sh
./update_and_restart_server.sh
```

El script hace:
1. ✅ Mata el servidor Flask viejo
2. ✅ Actualiza el código desde GitHub (`git pull`)
3. ✅ Verifica que Zeek esté instalado
4. ✅ Prueba la importación de módulos Python
5. ✅ Inicia el servidor Flask nuevo
6. ✅ Muestra el estado final

---

### Opción 2: Comando Todo-en-Uno 🚀

```bash
ssh root@195.26.243.120 "cd /home/Security2 && pkill -9 -f 'python.*app.py' && git pull origin main && source .venv/bin/activate && nohup python app.py > flask_server.log 2>&1 & sleep 3 && ps aux | grep '[p]ython.*app.py'"
```

Este comando hace lo mismo pero en una sola línea.

---

### Opción 3: Manual Paso a Paso 📋

```bash
# 1. Conectarte
ssh root@195.26.243.120

# 2. Ir al directorio
cd /home/Security2

# 3. Detener Flask
pkill -9 -f 'python.*app.py'

# 4. Actualizar código
git pull origin main

# 5. Activar entorno virtual
source .venv/bin/activate

# 6. Iniciar servidor
nohup python app.py > flask_server.log 2>&1 &

# 7. Verificar
sleep 3
ps aux | grep '[p]ython.*app.py'
```

---

## Verificar que Funciona

### 1. En la Terminal del Servidor

```bash
# Probar detección de Zeek
cd /home/Security2
source .venv/bin/activate

python3 << 'EOF'
import sys
sys.path.insert(0, '.')
from modules.zeek_manager import ZeekManager
from database.db_manager import DatabaseManager

db = DatabaseManager()
zm = ZeekManager(db)

print(f"✓ Zeek binary: {zm.zeek_binary}")
print(f"✓ Zeekctl binary: {zm.zeekctl_binary}")

status = zm.check_zeek_installed()
print(f"✓ Instalado: {status['installed']}")
print(f"✓ Versión: {status.get('version')}")

interfaces = zm.get_interfaces()
print(f"✓ Interfaces: {[i['name'] for i in interfaces]}")
print(f"✓ Interfaz por defecto: {zm.get_default_interface()}")
EOF
```

**Salida esperada:**
```
✓ Zeek binary: /opt/zeek/bin/zeek
✓ Zeekctl binary: /opt/zeek/bin/zeekctl
✓ Instalado: True
✓ Versión: zeek version 7.0.11
✓ Interfaces: ['eth0']
✓ Interfaz por defecto: eth0
```

### 2. En el Panel Web

1. Abre tu navegador
2. Ve a: `http://195.26.243.120:5000`
3. Inicia sesión con tus credenciales
4. En el menú lateral, busca **Network Monitor**
5. Haz clic en **Zeek Dashboard**

**Deberías ver:**
```
✅ Zeek Instalado: Sí
✅ Versión: zeek version 7.0.11
✅ Estado: Detenido (inicialmente)
✅ Interfaz detectada: eth0
```

### 3. Iniciar Zeek desde el Panel Web

1. Ve a **Network Monitor** → **Config Zeek**
2. Selecciona la interfaz: **eth0**
3. Haz clic en el botón verde **Iniciar**
4. Espera 5-10 segundos
5. Regresa a **Zeek Dashboard**
6. Deberías ver: **Estado: Corriendo** ✅

---

## Archivos Creados/Modificados

### Archivos Modificados
1. **modules/zeek_manager.py** - Agregado sudo, auto-detección de interfaz
2. **.claude/settings.local.json** - Permisos de git

### Archivos Nuevos
1. **update_and_restart_server.sh** - Script de actualización automática
2. **INSTRUCCIONES_ACTUALIZAR_SERVIDOR.md** - Instrucciones detalladas
3. **diagnostic_zeek.sh** - Script de diagnóstico
4. **INSTRUCCIONES_DIAGNOSTICO.md** - Guía de diagnóstico
5. **SOLUCION_ZEEK_NO_DETECTADO.md** - Este archivo (resumen del problema)

---

## Commits Realizados

### Commit 1: Fixes de Zeek
```
commit 1d23695
fix: Add sudo support for Zeek operations and improve interface detection

- Add sudo to zeekctl commands (status, deploy, stop) for proper permissions
- Implement get_default_interface() to auto-detect eth0 or best interface
- Improve get_interfaces() to filter out docker/veth/loopback interfaces
- Update _update_node_cfg() to use sudo when writing config files
- Add diagnostic script and instructions for troubleshooting
```

### Commit 2: Documentación
```
commit 5093f1b
docs: Add server update script and instructions for Zeek activation

- Add update_and_restart_server.sh for automatic server update
- Add detailed instructions in INSTRUCCIONES_ACTUALIZAR_SERVIDOR.md
```

---

## Próximos Pasos

### 1. Actualizar el Servidor (AHORA)
```bash
ssh root@195.26.243.120
cd /home/Security2
git pull
chmod +x update_and_restart_server.sh
./update_and_restart_server.sh
```

### 2. Verificar en el Panel Web
- Abre `http://195.26.243.120:5000`
- Ve a **Network Monitor** → **Zeek Dashboard**
- Verifica que detecte Zeek 7.0.11

### 3. Iniciar Zeek
- Ve a **Config Zeek**
- Selecciona interfaz **eth0**
- Haz clic en **Iniciar**

### 4. Ver Logs y Detecciones
- **Zeek Logs** - Ver logs de conexiones, DNS, SSL, HTTP
- **Detecciones** - Ver port scans, DNS tunneling, beaconing

---

## Resumen Visual

### Antes ❌
```
Panel Web → "Zeek no detectado"
           ↓
    zeek_manager.py (sin sudo)
           ↓
    /opt/zeek/bin/zeekctl status
           ↓
    "zeekctl: command not found"
```

### Después ✅
```
Panel Web → "Zeek 7.0.11 instalado"
           ↓
    zeek_manager.py (con sudo)
           ↓
    sudo /opt/zeek/bin/zeekctl status
           ↓
    "zeek running"
```

---

## Preguntas Frecuentes

### ¿Por qué no funcionaba antes?
El código necesitaba `sudo` para ejecutar comandos de `zeekctl`, y el servidor Flask no se había reiniciado después de instalar Zeek.

### ¿Necesito reinstalar Zeek?
**NO.** Zeek ya está correctamente instalado. Solo necesitas actualizar el código y reiniciar Flask.

### ¿Qué hace exactamente el script de actualización?
1. Mata el proceso Flask viejo
2. Actualiza el código con `git pull`
3. Verifica que Zeek esté instalado
4. Prueba los módulos Python
5. Inicia Flask nuevamente

### ¿Puedo usar esto en producción?
Sí, el código usa `sudo` de forma segura y solo para comandos específicos de Zeek.

### ¿Qué pasa si tengo múltiples interfaces?
El sistema auto-detecta y prefiere `eth0`, pero puedes seleccionar manualmente desde el panel web.

---

## Soporte

Si después de actualizar el servidor aún no funciona:

1. **Ver logs del servidor Flask:**
   ```bash
   tail -f /home/Security2/flask_server.log
   ```

2. **Ejecutar diagnóstico:**
   ```bash
   cd /home/Security2
   chmod +x diagnostic_zeek.sh
   ./diagnostic_zeek.sh
   ```

3. **Verificar que Zeek esté instalado:**
   ```bash
   /opt/zeek/bin/zeek --version
   sudo /opt/zeek/bin/zeekctl status
   ```

4. **Ver estado de las interfaces:**
   ```bash
   ip link show
   ip addr show eth0
   ```

---

**¡Listo para actualizar! Ejecuta el script y Zeek funcionará en tu panel web.** 🚀
