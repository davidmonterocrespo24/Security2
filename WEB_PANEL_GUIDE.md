# Guía del Panel Web de Seguridad

## 🎯 Configurar Protecciones desde el Panel Web

Ahora puedes configurar **todas las protecciones de Fail2ban directamente desde el panel web**, sin necesidad de editar archivos manualmente en el servidor.

---

## 📍 Acceso al Panel

### 1. Desplegar en tu Servidor Ubuntu

```bash
# En tu servidor Ubuntu
cd /ruta/del/proyecto
sudo bash deploy_to_server.sh
```

### 2. Acceder desde tu Navegador (Windows, Mac, Linux, cualquier dispositivo)

```
http://IP-DE-TU-SERVIDOR:5000
```

Ejemplo:
- `http://192.168.1.100:5000`
- `http://tuservidor.com:5000`

### 3. Login

```
Usuario: admin
Contraseña: Montero25
```

(O las credenciales que configuraste en `.env`)

---

## 🛡️ Configurar Protecciones Automáticas

Ve a la sección **"Fail2ban"** en el menú lateral.

### Protección 1: Límite de Peticiones HTTP (Anti-DDoS/Flooding)

**Propósito:** Bloquear automáticamente IPs que hagan demasiadas peticiones HTTP.

**Cómo configurar:**

1. Haz clic en **"Configurar"** en la tarjeta **"Límite de Peticiones HTTP"**

2. Ajusta los parámetros:

   - **Máximo de Peticiones (maxretry):**
     `100` = Bloquear después de 100 peticiones
     _Sugerido: 100-200 para sitios normales, 30-50 para ser agresivo_

   - **Tiempo de Ventana (findtime):**
     `60` segundos = Contar peticiones en 1 minuto
     _Sugerido: 60 segundos_

   - **Tiempo de Bloqueo (bantime):**
     `3600` segundos = Banear por 1 hora
     _Sugerido: 3600 (1 hora) o 7200 (2 horas)_

   - **Ruta del Log de Nginx:**
     `/var/log/nginx/access.log`
     _Ajusta según tu instalación_

3. Haz clic en **"Crear Jail"**

4. ¡Listo! La protección está activa.

**Ejemplo de Configuración Agresiva:**
```
maxretry: 50
findtime: 30
bantime: 7200
```
→ Bloqueará IPs que hagan **más de 50 peticiones en 30 segundos** por **2 horas**.

**Ejemplo de Configuración Balanceada:**
```
maxretry: 100
findtime: 60
bantime: 3600
```
→ Bloqueará IPs que hagan **más de 100 peticiones en 60 segundos** por **1 hora**.

---

### Protección 2: Bloqueo de Bots Maliciosos

**Propósito:** Detectar y bloquear bots maliciosos, scrapers, herramientas de hacking.

**Bots que SE BLOQUEAN:**
- curl, wget, python-requests, axios
- scrapers, spiders
- nikto, sqlmap, nmap (herramientas de hacking)
- Otros bots maliciosos

**Bots que NO SE BLOQUEAN (whitelisted):**
- Googlebot
- Bingbot
- YandexBot
- Baiduspider

**Cómo configurar:**

1. Haz clic en **"Configurar"** en la tarjeta **"Bloqueo de Bots Maliciosos"**

2. Ajusta los parámetros:

   - **Máximo de Peticiones:** `50`
   - **Tiempo de Ventana:** `300` segundos (5 minutos)
   - **Tiempo de Bloqueo:** `7200` segundos (2 horas)
   - **Ruta del Log:** `/var/log/nginx/access.log`

3. Haz clic en **"Crear Jail"**

4. ¡Listo! Los bots maliciosos serán bloqueados automáticamente.

---

## 📊 Ver Estadísticas y Bloqueos

### Ver IPs Bloqueadas

1. En la página de Fail2ban, baja hasta la sección **"IPs Bloqueadas"**

2. Selecciona la jail en el dropdown:
   - `sshd` - IPs bloqueadas por intentos SSH fallidos
   - `nginx-req-limit` - IPs bloqueadas por exceso de peticiones
   - `http-bot-blocker` - Bots maliciosos bloqueados

3. Verás la lista de IPs bloqueadas con opción de **desbloquear**.

### Ver Estado de las Jails

Las tarjetas de jails muestran:
- **IPs Bloqueadas actuales**
- **Total de IPs bloqueadas históricamente**
- **Intentos fallidos**
- **Estado (Activo/Inactivo)**

---

## 🔧 Gestión de IPs

### Bloquear una IP Manualmente

1. En la sección **"Bloquear IP Manualmente"**
2. Ingresa la IP: `123.456.789.0`
3. Selecciona la jail: `nginx-req-limit` o `http-bot-blocker`
4. Haz clic en **"Bloquear"**

### Desbloquear una IP

1. Busca la IP en la tabla de **"IPs Bloqueadas"**
2. Haz clic en **"Desbloquear"**
3. Confirma

---

## ⚙️ Configuraciones Recomendadas por Escenario

### Sitio Web Normal (Blog, Corporativo)

**Rate Limit:**
```
maxretry: 200
findtime: 60
bantime: 1800
```

**Bot Blocker:**
```
maxretry: 50
findtime: 300
bantime: 7200
```

### API REST o Aplicación Web

**Rate Limit:**
```
maxretry: 100
findtime: 60
bantime: 3600
```

**Bot Blocker:**
```
maxretry: 30
findtime: 180
bantime: 10800
```

### E-commerce con Mucho Tráfico

**Rate Limit:**
```
maxretry: 300
findtime: 60
bantime: 900
```

**Bot Blocker:**
```
maxretry: 100
findtime: 300
bantime: 3600
```

### Servidor Bajo Ataque

**Rate Limit (SUPER AGRESIVO):**
```
maxretry: 30
findtime: 10
bantime: 86400  # 24 horas
```

**Bot Blocker (SUPER AGRESIVO):**
```
maxretry: 20
findtime: 60
bantime: 86400  # 24 horas
```

---

## 🧪 Probar que Funciona

### Desde otra máquina:

```bash
# Hacer 150 peticiones rápidas
for i in {1..150}; do
    curl http://tu-servidor.com/ -s -o /dev/null
    echo "Petición $i"
done
```

**Resultado esperado:**
Después de ~100 peticiones (según tu configuración), la IP será bloqueada y verás errores de conexión.

### Verificar en el Panel Web:

1. Ve a Fail2ban
2. Selecciona jail `nginx-req-limit` en el dropdown de IPs bloqueadas
3. Deberías ver la IP en la lista

---

## 📱 Acceso Remoto

El panel web funciona desde **cualquier dispositivo** en tu red:

- 💻 **Desde tu PC Windows:** `http://IP-SERVIDOR:5000`
- 📱 **Desde tu teléfono:** `http://IP-SERVIDOR:5000`
- 🍎 **Desde tu Mac:** `http://IP-SERVIDOR:5000`
- 🐧 **Desde otra máquina Linux:** `http://IP-SERVIDOR:5000`

Solo necesitas:
1. Que el servidor esté ejecutando el panel (`sudo systemctl start security-system`)
2. Que el firewall permita el puerto 5000 (`sudo ufw allow 5000/tcp`)
3. Conocer la IP de tu servidor

---

## 🔒 Seguridad del Panel Web

### Cambiar Credenciales

En el servidor, edita `.env`:

```bash
nano /opt/security-system/.env
```

Cambia:
```env
ADMIN_USERNAME=tu_nuevo_usuario
ADMIN_PASSWORD=tu_nueva_contraseña_segura
```

Reinicia:
```bash
sudo systemctl restart security-system
```

### Restringir Acceso por IP (Opcional)

Si solo quieres acceder desde tu IP de oficina:

```bash
# En lugar de permitir 0.0.0.0:5000, usa tu IP específica
# Edita .env:
HOST=192.168.1.50  # Solo accesible desde esta IP
```

O configura un firewall para solo permitir tu IP:

```bash
sudo ufw delete allow 5000/tcp
sudo ufw allow from TU_IP to any port 5000
```

### Configurar HTTPS (Recomendado para producción)

Ver: [UBUNTU_DEPLOYMENT.md](UBUNTU_DEPLOYMENT.md) sección "Configurar Nginx como Reverse Proxy"

---

## 🆘 Troubleshooting

### No puedo acceder al panel

**Problema:** `http://IP:5000` no carga

**Soluciones:**

1. Verificar que el servicio está corriendo:
   ```bash
   sudo systemctl status security-system
   ```

2. Verificar que el firewall permite el puerto:
   ```bash
   sudo ufw status | grep 5000
   ```

3. Verificar que el servidor escucha en 0.0.0.0:
   ```bash
   cat /opt/security-system/.env | grep HOST
   # Debe ser: HOST=0.0.0.0
   ```

### Las jails no se crean

**Problema:** Al crear una jail, sale error

**Soluciones:**

1. Verificar permisos sudo:
   ```bash
   sudo -l | grep fail2ban
   ```

2. Verificar que fail2ban está corriendo:
   ```bash
   sudo systemctl status fail2ban
   ```

3. Ver logs del panel:
   ```bash
   sudo journalctl -u security-system -n 50
   ```

### Los bots no se bloquean

**Problema:** Los bots siguen haciendo peticiones

**Soluciones:**

1. Verificar que la ruta del log es correcta:
   ```bash
   ls -la /var/log/nginx/access.log
   ```

2. Verificar que el filtro funciona:
   ```bash
   sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/http-bot-blocker.conf
   ```

3. Ver logs de fail2ban:
   ```bash
   sudo tail -f /var/log/fail2ban.log | grep bot-blocker
   ```

---

## 📚 Recursos Adicionales

- **Instalación Completa:** [UBUNTU_DEPLOYMENT.md](UBUNTU_DEPLOYMENT.md)
- **Configuración de Fail2ban Manual:** [FAIL2BAN_SETUP.md](FAIL2BAN_SETUP.md)
- **Solución Rápida:** [SOLUCION_RAPIDA.md](SOLUCION_RAPIDA.md)
- **Login del Sistema:** [LOGIN_INFO.md](LOGIN_INFO.md)

---

## ✅ Resumen

**LO QUE PUEDES HACER DESDE EL PANEL WEB:**

✅ Configurar límites de peticiones HTTP (anti-DDoS)
✅ Configurar bloqueo de bots maliciosos
✅ Ver IPs bloqueadas en tiempo real
✅ Desbloquear IPs manualmente
✅ Bloquear IPs manualmente
✅ Ver estadísticas de cada jail
✅ Activar/desactivar jails
✅ Todo desde cualquier dispositivo con navegador

**LO QUE NO NECESITAS HACER:**

❌ Editar archivos de configuración manualmente
❌ Conectarte por SSH para cada cambio
❌ Usar comandos de terminal
❌ Reiniciar servicios manualmente

**¡TODO SE HACE DESDE EL NAVEGADOR!** 🎉
