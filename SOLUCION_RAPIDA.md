# 🚨 SOLUCIÓN RÁPIDA - Bloquear IPs con 100+ Peticiones

## El Problema

Hiciste **100 peticiones en menos de 1 minuto** y Fail2ban **NO bloqueó la IP**.

**Razón**: Fail2ban está instalado pero no tiene configurado ningún filtro/jail para detectar peticiones HTTP abusivas en Nginx.

---

## ✅ SOLUCIÓN EN 3 PASOS

### PASO 1: Copiar el script de instalación

Desde tu máquina Windows:

```bash
scp install_fail2ban_filters.sh tu-usuario@tu-servidor:/tmp/
```

### PASO 2: Ejecutar en tu servidor Ubuntu

```bash
ssh tu-usuario@tu-servidor
cd /tmp
chmod +x install_fail2ban_filters.sh
sudo bash install_fail2ban_filters.sh
```

**Listo.** El script instalará automáticamente todo lo necesario.

### PASO 3: Verificar que funciona

```bash
sudo fail2ban-client status nginx-req-limit
```

Deberías ver:
```
Status for the jail: nginx-req-limit
|- Filter
|  |- Currently failed: 0
|  |- Total failed:     0
|  `- File list:        /var/log/nginx/access.log
`- Actions
   |- Currently banned: 0
   |- Total banned:     0
   `- Banned IP list:
```

---

## 🧪 PROBAR QUE FUNCIONA

### Desde otra máquina o servidor:

```bash
# Hacer 150 peticiones rápidas
for i in {1..150}; do curl http://tu-servidor.com/ -s -o /dev/null; echo $i; done
```

Después de ~100 peticiones, deberías recibir un error de conexión.

### Verificar el bloqueo:

```bash
sudo fail2ban-client status nginx-req-limit
# Verás la IP en "Banned IP list"

sudo tail -20 /var/log/fail2ban.log
# Verás: "Ban 123.456.789.0"
```

---

## ⚙️ CONFIGURACIÓN INSTALADA

```ini
Jail: nginx-req-limit
├─ Máximo de peticiones: 100
├─ Tiempo de ventana: 60 segundos
└─ Tiempo de ban: 3600 segundos (1 hora)
```

**Esto significa:**
- Si una IP hace **más de 100 peticiones en 60 segundos** → Se bloquea por 1 hora

---

## 📊 COMANDOS ÚTILES

```bash
# Ver todas las jails activas
sudo fail2ban-client status

# Ver IPs bloqueadas
sudo fail2ban-client status nginx-req-limit | grep "Banned IP"

# Desbloquear una IP
sudo fail2ban-client set nginx-req-limit unbanip 123.456.789.0

# Ver logs en tiempo real
sudo tail -f /var/log/fail2ban.log | grep "Ban"

# Ver últimos bloqueos
sudo grep "Ban" /var/log/fail2ban.log | tail -20
```

---

## 🔧 AJUSTAR CONFIGURACIÓN

Si quieres ser **MÁS AGRESIVO** (50 peticiones en 30 segundos):

```bash
sudo nano /etc/fail2ban/jail.d/nginx-req-limit.local
```

Cambiar:
```ini
maxretry = 50
findtime = 30
bantime = 7200
```

Reiniciar:
```bash
sudo systemctl restart fail2ban
```

Si quieres ser **MENOS AGRESIVO** (200 peticiones en 60 segundos):

```ini
maxretry = 200
findtime = 60
bantime = 1800
```

---

## ⚠️ IMPORTANTE: Ubicación del Log de Nginx

El script buscará automáticamente tu log de Nginx en:
- `/var/log/nginx/access.log` (ubicación estándar)
- `/var/log/nginx/access_log`
- `/opt/odoo/nginx/logs/access.log`

Si tu log está en otra ubicación:

```bash
sudo nano /etc/fail2ban/jail.d/nginx-req-limit.local
```

Cambiar:
```ini
logpath = /ruta/a/tu/nginx/access.log
```

Reiniciar:
```bash
sudo systemctl restart fail2ban
```

---

## 🎯 RESUMEN

**ANTES:**
- ❌ 100 peticiones en 1 minuto → No pasa nada
- ❌ IP no bloqueada
- ❌ Sin protección contra DDoS/flooding

**DESPUÉS:**
- ✅ 100 peticiones en 1 minuto → IP bloqueada automáticamente
- ✅ Bloqueada por 1 hora
- ✅ Protección activa contra ataques

---

## 📚 Documentación Completa

- **Guía detallada**: Ver [FAIL2BAN_SETUP.md](FAIL2BAN_SETUP.md)
- **Deployment en Ubuntu**: Ver [UBUNTU_DEPLOYMENT.md](UBUNTU_DEPLOYMENT.md)
- **Script de prueba**: Ver [test_fail2ban.py](test_fail2ban.py)

---

## ❓ ¿Necesitas ayuda?

Si el script no funciona:

1. Verifica que Fail2ban esté corriendo:
   ```bash
   sudo systemctl status fail2ban
   ```

2. Verifica que el log de Nginx existe:
   ```bash
   ls -la /var/log/nginx/access.log
   ```

3. Verifica los errores de Fail2ban:
   ```bash
   sudo journalctl -u fail2ban -n 50
   ```

4. Prueba el filtro manualmente:
   ```bash
   sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/nginx-req-limit-aggressive.conf
   ```

---

**¡Ahora tu servidor está protegido contra peticiones abusivas!** 🛡️
