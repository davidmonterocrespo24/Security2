# Diagnóstico: No Aparecen Logs de Zeek

## Posibles Causas

1. **Zeek no está iniciado** - El servicio está instalado pero no corriendo
2. **Zeek está corriendo pero no genera logs** - Problema de permisos o interfaz incorrecta
3. **Los logs existen pero no se han importado a la BD** - Necesitas importarlos manualmente
4. **La ruta de logs es incorrecta** - Zeek guarda en un lugar diferente

---

## Diagnóstico Rápido

### Paso 1: Verificar estado de Zeek

Ejecuta en el servidor:

```bash
ssh root@195.26.243.120
cd /home/Security2
git pull
chmod +x check_zeek_status.sh
./check_zeek_status.sh
```

Este script te dirá:
1. ✅ Si Zeek está corriendo
2. 📁 Dónde están los logs
3. 📊 Cuántos registros hay en la base de datos
4. 🔧 Configuración de la interfaz

**Copia y pégame la salida completa.**

---

## Soluciones Comunes

### Solución 1: Iniciar Zeek si no está corriendo

```bash
cd /home/Security2
source .venv/bin/activate

# Iniciar Zeek con la interfaz eth0
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

Deberías ver:
```
Name         Type       Host          Status    Pid    Started
zeek         standalone localhost     running   12345  18 Nov 10:30:00
```

---

### Solución 2: Importar logs existentes a la BD

Si Zeek está corriendo y generando logs, pero no aparecen en el dashboard, necesitas importarlos:

**Opción A: Desde el Panel Web**

1. Ve a: `http://195.26.243.120:5000`
2. Network Monitor → **Zeek Dashboard**
3. Busca el botón **"Importar Logs"** o **"Actualizar Datos"**
4. Haz clic y espera 10-30 segundos

**Opción B: Desde la Terminal**

```bash
cd /home/Security2
source .venv/bin/activate

python3 << 'EOF'
import sys
sys.path.insert(0, '.')

from database.db_manager import DatabaseManager
from modules.zeek_analyzer import ZeekAnalyzer

db = DatabaseManager()
analyzer = ZeekAnalyzer(db)

print("Importando logs de Zeek a la base de datos...")
result = analyzer.import_zeek_logs_to_db(log_type='all', limit=1000)

print(f"\nResultado:")
print(f"  Conexiones importadas: {result.get('connections_imported', 0)}")
print(f"  DNS importados: {result.get('dns_imported', 0)}")
print(f"  HTTP importados: {result.get('http_imported', 0)}")
print(f"  SSL importados: {result.get('ssl_imported', 0)}")
EOF
```

---

### Solución 3: Verificar permisos de captura

```bash
# Verificar que zeek tenga permisos para capturar paquetes
sudo /opt/zeek/bin/zeek -i eth0 local &
sleep 10
sudo pkill zeek

# Verificar que se generaron logs
ls -lh /opt/zeek/logs/current/
```

---

### Solución 4: Configurar interfaz correcta

```bash
# Editar node.cfg
sudo nano /opt/zeek/etc/node.cfg

# Buscar la línea:
# interface=ens3  (o similar)

# Cambiarla por:
# interface=eth0

# Guardar (Ctrl+O, Enter, Ctrl+X)

# Redeployar Zeek
sudo /opt/zeek/bin/zeekctl deploy
```

---

## Script de Importación Automática

Puedes crear un cron job para importar logs cada 5 minutos:

```bash
# Crear script de importación
cat > /home/Security2/import_zeek_logs.sh << 'EOF'
#!/bin/bash
cd /home/Security2
source .venv/bin/activate
python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
from database.db_manager import DatabaseManager
from modules.zeek_analyzer import ZeekAnalyzer

db = DatabaseManager()
analyzer = ZeekAnalyzer(db)
analyzer.import_zeek_logs_to_db(log_type='all', limit=500)
PYEOF
EOF

# Dar permisos
chmod +x /home/Security2/import_zeek_logs.sh

# Agregar a crontab (cada 5 minutos)
(crontab -l 2>/dev/null; echo "*/5 * * * * /home/Security2/import_zeek_logs.sh >> /home/Security2/zeek_import.log 2>&1") | crontab -
```

---

## Verificación en el Panel Web

Después de hacer la importación, ve al panel web:

1. **Network Monitor** → **Zeek Dashboard**
   - Debe mostrar estadísticas (conexiones, DNS, HTTP, SSL)
   - Gráficos de tráfico
   - Top IPs

2. **Network Monitor** → **Logs de Zeek**
   - Pestaña **Conexiones** - Debe mostrar tráfico de red
   - Pestaña **DNS** - Consultas DNS capturadas
   - Pestaña **HTTP** - Peticiones HTTP
   - Pestaña **SSL** - Conexiones HTTPS

3. **Network Monitor** → **Detecciones**
   - Port scans detectados
   - DNS tunneling
   - Certificados sospechosos

---

## Checklist de Verificación

Marca lo que ya verificaste:

- [ ] Zeek está instalado (`/opt/zeek/bin/zeek --version`)
- [ ] Zeek está corriendo (`sudo /opt/zeek/bin/zeekctl status`)
- [ ] Existen archivos de log (`ls /opt/zeek/logs/current/`)
- [ ] Los logs tienen contenido (`tail /opt/zeek/logs/current/conn.log`)
- [ ] La interfaz es correcta (`cat /opt/zeek/etc/node.cfg | grep interface`)
- [ ] La base de datos tiene registros (script de verificación)
- [ ] El servidor Flask está corriendo (`ps aux | grep app.py`)
- [ ] No hay errores en los logs de Flask (`tail -f flask_server.log`)

---

## Comandos Útiles

### Ver logs en tiempo real

```bash
# Logs de conexiones
tail -f /opt/zeek/logs/current/conn.log

# Logs de DNS
tail -f /opt/zeek/logs/current/dns.log

# Logs de HTTP
tail -f /opt/zeek/logs/current/http.log
```

### Reiniciar Zeek

```bash
sudo /opt/zeek/bin/zeekctl stop
sleep 2
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl status
```

### Ver estadísticas de Zeek

```bash
sudo /opt/zeek/bin/zeekctl netstats
```

---

## Próximos Pasos

1. **Ejecuta el script de diagnóstico** y pégame la salida
2. Basado en eso, te diré exactamente qué hacer
3. Importamos los logs a la base de datos
4. Verificamos que aparezcan en el dashboard

**¿Puedes ejecutar `./check_zeek_status.sh` en el servidor y pegarme el resultado?**
