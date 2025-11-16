# Guía de Configuración de Fail2ban para Bloqueo de IPs

## Problema Identificado

Hiciste 100 peticiones en menos de 1 minuto y Fail2ban **NO bloqueó la IP** porque:

1. ❌ No hay filtros configurados para detectar peticiones HTTP rápidas
2. ❌ No hay jails activas para monitorear el log de Nginx
3. ❌ La configuración por defecto de Fail2ban solo protege SSH

## Solución

He creado filtros y jails específicos para detectar y bloquear IPs que hagan demasiadas peticiones.

---

## Instalación Rápida (Recomendado)

### Paso 1: Copiar archivos al servidor

```bash
# Desde tu máquina Windows/local
scp install_fail2ban_filters.sh tu-usuario@tu-servidor:/tmp/

# Conectar al servidor
ssh tu-usuario@tu-servidor
```

### Paso 2: Ejecutar el script de instalación

```bash
cd /tmp
chmod +x install_fail2ban_filters.sh
sudo bash install_fail2ban_filters.sh
```

El script instalará automáticamente:
- ✅ Filtro `nginx-req-limit-aggressive.conf`
- ✅ Filtro `nginx-req-limit.conf`
- ✅ Jail `nginx-req-limit` (100 peticiones en 60 segundos)
- ✅ Jail `nginx-req-limit-super` (30 peticiones en 10 segundos - deshabilitado)

### Paso 3: Verificar que funciona

```bash
# Ver estado de la jail
sudo fail2ban-client status nginx-req-limit

# Debería mostrar algo como:
# Status for the jail: nginx-req-limit
# |- Filter
# |  |- Currently failed: 0
# |  |- Total failed:     0
# |  `- File list:        /var/log/nginx/access.log
# `- Actions
#    |- Currently banned: 0
#    |- Total banned:     0
#    `- Banned IP list:
```

---

## Instalación Manual (Paso a Paso)

Si prefieres instalar manualmente:

### 1. Crear el filtro

```bash
sudo nano /etc/fail2ban/filter.d/nginx-req-limit-aggressive.conf
```

Contenido:
```ini
[Definition]
failregex = ^<HOST> -.*"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS).*HTTP.*"
ignoreregex =

[Init]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
```

### 2. Crear la jail

```bash
sudo nano /etc/fail2ban/jail.d/nginx-req-limit.local
```

Contenido:
```ini
[nginx-req-limit]
enabled = true
port = http,https
filter = nginx-req-limit-aggressive
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime = 3600
action = %(action_mwl)s
```

**Importante**: Ajusta `logpath` a la ubicación real de tu log de Nginx:
- `/var/log/nginx/access.log` (ubicación estándar)
- `/var/log/nginx/odoo/access.log` (si tienes Odoo)
- Ejecuta `sudo find /var/log -name "*access.log"` para encontrarlo

### 3. Reiniciar Fail2ban

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status
```

---

## Configuraciones Disponibles

### Configuración Balanceada (Recomendada)

```ini
[nginx-req-limit]
enabled = true
maxretry = 100    # Bloquear después de 100 peticiones
findtime = 60     # En 60 segundos
bantime = 3600    # Banear por 1 hora
```

**Bloquea**: IPs que hagan más de 100 peticiones en 1 minuto

### Configuración Agresiva

```ini
[nginx-req-limit]
enabled = true
maxretry = 50     # Bloquear después de 50 peticiones
findtime = 30     # En 30 segundos
bantime = 7200    # Banear por 2 horas
```

**Bloquea**: IPs que hagan más de 50 peticiones en 30 segundos

### Configuración Super Agresiva (⚠️ Cuidado)

```ini
[nginx-req-limit-super]
enabled = true
maxretry = 30     # Bloquear después de 30 peticiones
findtime = 10     # En 10 segundos
bantime = 14400   # Banear por 4 horas
```

**Bloquea**: IPs que hagan más de 30 peticiones en 10 segundos

**⚠️ Advertencia**: Puede bloquear usuarios legítimos o crawlers de Google

---

## Comandos Útiles

### Ver estado de las jails

```bash
# Todas las jails
sudo fail2ban-client status

# Solo nginx-req-limit
sudo fail2ban-client status nginx-req-limit
```

### Ver IPs bloqueadas

```bash
sudo fail2ban-client status nginx-req-limit | grep "Banned IP"
```

### Desbloquear una IP

```bash
sudo fail2ban-client set nginx-req-limit unbanip 123.456.789.0
```

### Bloquear una IP manualmente

```bash
sudo fail2ban-client set nginx-req-limit banip 123.456.789.0
```

### Ver logs en tiempo real

```bash
# Logs de fail2ban
sudo tail -f /var/log/fail2ban.log

# Filtrar solo bloqueos
sudo tail -f /var/log/fail2ban.log | grep "Ban"

# Ver últimos 50 bloqueos
sudo grep "Ban" /var/log/fail2ban.log | tail -n 50
```

### Ver estadísticas

```bash
# Total de IPs baneadas actualmente
sudo fail2ban-client status nginx-req-limit | grep "Currently banned"

# Total de IPs baneadas históricamente
sudo fail2ban-client status nginx-req-limit | grep "Total banned"
```

---

## Probar que Funciona

### Método 1: Usando curl (desde otra máquina)

```bash
# Hacer 150 peticiones rápidas
for i in {1..150}; do
    curl http://tu-servidor.com/ -s -o /dev/null
    echo "Petición $i"
done
```

Después de ~100 peticiones, deberías recibir un error de conexión (IP bloqueada).

### Método 2: Usando Apache Bench

```bash
# Instalar ab
sudo apt install apache2-utils -y

# Hacer 200 peticiones, 10 concurrentes
ab -n 200 -c 10 http://tu-servidor.com/
```

### Método 3: Usando Python

```python
import requests
import time

url = "http://tu-servidor.com/"

for i in range(150):
    try:
        response = requests.get(url, timeout=5)
        print(f"Petición {i+1}: {response.status_code}")
        time.sleep(0.1)  # Pequeña pausa entre peticiones
    except Exception as e:
        print(f"Petición {i+1}: ERROR - {e}")
        print("¡Probablemente bloqueado!")
        break
```

### Verificar el bloqueo

```bash
# Ver si tu IP fue bloqueada
sudo fail2ban-client status nginx-req-limit

# Ver el log
sudo tail -20 /var/log/fail2ban.log
```

Deberías ver algo como:
```
2025-11-16 16:45:23,456 fail2ban.actions [12345]: NOTICE [nginx-req-limit] Ban 123.456.789.0
```

---

## Whitelist (No Bloquear IPs Específicas)

Si quieres que ciertas IPs NUNCA sean bloqueadas:

```bash
sudo nano /etc/fail2ban/jail.d/nginx-req-limit.local
```

Agregar:
```ini
[nginx-req-limit]
enabled = true
ignoreip = 127.0.0.1/8 ::1
           123.456.789.0    # Tu IP de oficina
           10.0.0.0/8       # Red local
maxretry = 100
findtime = 60
bantime = 3600
```

Reiniciar:
```bash
sudo systemctl restart fail2ban
```

---

## Troubleshooting

### Problema: La jail no aparece

```bash
# Ver errores
sudo journalctl -u fail2ban -n 50

# Verificar sintaxis del filtro
sudo fail2ban-client -t

# Reiniciar fail2ban
sudo systemctl restart fail2ban
```

### Problema: No detecta peticiones

```bash
# Verificar que el log existe
ls -la /var/log/nginx/access.log

# Verificar permisos
sudo chmod +r /var/log/nginx/access.log

# Ver en tiempo real
sudo tail -f /var/log/nginx/access.log
```

### Problema: El filtro no funciona

```bash
# Probar el filtro manualmente
sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/nginx-req-limit-aggressive.conf

# Debería mostrar cuántas líneas coinciden
```

### Problema: Bloqueó mi IP por error

```bash
# Desbloquear inmediatamente
sudo fail2ban-client set nginx-req-limit unbanip TU_IP

# O agregar a whitelist (ver arriba)
```

---

## Integración con el Panel Web

Una vez configurado, el panel web de seguridad mostrará:

- ✅ IPs bloqueadas en tiempo real
- ✅ Estadísticas de bloqueos
- ✅ Jails activas
- ✅ Logs de Fail2ban
- ✅ Opción de desbloquear IPs desde la interfaz

Para que el panel detecte Fail2ban:

1. Asegúrate de que el servicio esté corriendo: `sudo systemctl status fail2ban`
2. El panel detectará automáticamente `/usr/bin/fail2ban-client`
3. Ve a la sección "Fail2ban" en el panel web

---

## Monitoreo y Alertas

### Recibir emails cuando se bloquea una IP

```bash
sudo nano /etc/fail2ban/jail.d/nginx-req-limit.local
```

Agregar:
```ini
[nginx-req-limit]
enabled = true
destemail = admin@tudominio.com
sender = fail2ban@tudominio.com
mta = sendmail
action = %(action_mwl)s
```

### Ver estadísticas diarias

```bash
# Bloqueos de hoy
sudo grep "$(date +%Y-%m-%d)" /var/log/fail2ban.log | grep "Ban" | wc -l

# Top 10 IPs bloqueadas
sudo grep "Ban" /var/log/fail2ban.log | awk '{print $(NF)}' | sort | uniq -c | sort -rn | head -10
```

---

## Configuración Recomendada por Tipo de Sitio

### Sitio Web Normal (Blog, Corporativo)
```ini
maxretry = 200
findtime = 60
bantime = 1800
```

### API REST o Aplicación Web
```ini
maxretry = 100
findtime = 60
bantime = 3600
```

### Sitio con Mucho Tráfico (E-commerce)
```ini
maxretry = 300
findtime = 60
bantime = 900
```

### Servidor bajo Ataque DDoS
```ini
maxretry = 30
findtime = 10
bantime = 86400  # 24 horas
```

---

## Resumen

1. ✅ Instala los filtros y jails usando el script `install_fail2ban_filters.sh`
2. ✅ Verifica que funciona: `sudo fail2ban-client status nginx-req-limit`
3. ✅ Prueba haciendo 150 peticiones rápidas desde otra máquina
4. ✅ Monitorea los logs: `sudo tail -f /var/log/fail2ban.log`
5. ✅ Ajusta `maxretry`, `findtime` y `bantime` según tus necesidades

**Ahora tu servidor BLOQUEARÁ automáticamente IPs que hagan más de 100 peticiones en 60 segundos.**
