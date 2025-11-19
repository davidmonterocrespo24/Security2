# Guía de Despliegue en Ubuntu Server

## Prerequisitos

Tu servidor ya tiene instalado:
- ✅ Fail2ban (confirmado por `systemctl status fail2ban`)
- Sistema operativo: Ubuntu
- Python 3

## Paso 1: Copiar Archivos al Servidor

Desde tu máquina Windows, copia los archivos al servidor:

```bash
# Opción 1: Usando SCP
scp -r e:\Python\Security2\* tu-usuario@tu-servidor:/opt/security-system/

# Opción 2: Usando git (recomendado)
# En el servidor:
cd /opt
sudo mkdir security-system
sudo chown tu-usuario:tu-usuario security-system
git clone <tu-repositorio> security-system
```

## Paso 2: Instalar Dependencias en el Servidor

Conéctate a tu servidor Ubuntu:

```bash
ssh tu-usuario@tu-servidor
cd /opt/security-system
```

Instala las dependencias:

```bash
# Actualizar pip
sudo apt update
sudo apt install python3-pip -y

# Instalar dependencias del sistema
sudo apt install python3-venv -y

# Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias Python
pip install -r requirements.txt

# IMPORTANTE: En Ubuntu, descomentar python-iptables
# Editar requirements.txt y descomentar:
# python-iptables==1.0.1

# Reinstalar con python-iptables
pip install python-iptables
```

## Paso 3: Configurar Variables de Entorno

```bash
# Copiar ejemplo de .env
cp .env.example .env

# Editar .env
nano .env
```

Configurar credenciales y rutas:

```env
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=genera-una-clave-secreta-aleatoria-aqui
PORT=5000
HOST=0.0.0.0

# Credenciales de autenticación
ADMIN_USERNAME=admin
ADMIN_PASSWORD=TuContraseñaSegura123!
```

**IMPORTANTE**: Cambia `SECRET_KEY` y `ADMIN_PASSWORD` por valores seguros.

## Paso 4: Configurar Permisos de Sudo

El sistema necesita ejecutar comandos con sudo. Configura sudoers:

```bash
sudo visudo -f /etc/sudoers.d/security-system
```

Agrega estas líneas (reemplaza `tu-usuario` por tu usuario real):

```
# Comandos de Fail2ban
tu-usuario ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
tu-usuario ALL=(ALL) NOPASSWD: /bin/systemctl status fail2ban
tu-usuario ALL=(ALL) NOPASSWD: /bin/systemctl is-active fail2ban
tu-usuario ALL=(ALL) NOPASSWD: /bin/systemctl start fail2ban
tu-usuario ALL=(ALL) NOPASSWD: /bin/systemctl stop fail2ban
tu-usuario ALL=(ALL) NOPASSWD: /bin/systemctl restart fail2ban

# Comandos de UFW
tu-usuario ALL=(ALL) NOPASSWD: /usr/sbin/ufw

# Lectura de logs
tu-usuario ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/fail2ban.log
tu-usuario ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/auth.log
tu-usuario ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/nginx/*

# Instalación de paquetes (opcional, solo para setup)
tu-usuario ALL=(ALL) NOPASSWD: /usr/bin/apt-get update
tu-usuario ALL=(ALL) NOPASSWD: /usr/bin/apt-get install *
```

Guarda y sal (Ctrl+X, Y, Enter).

## Paso 5: Verificar que Fail2ban Está Detectado

```bash
# Verificar ruta de fail2ban-client
which fail2ban-client
# Debería mostrar: /usr/bin/fail2ban-client

# Verificar estado
sudo systemctl status fail2ban
# Debería mostrar: active (running)

# Probar comando
sudo /usr/bin/fail2ban-client status
# Debería mostrar las jails configuradas
```

## Paso 6: Ejecutar la Aplicación

### Opción 1: Modo Desarrollo (para pruebas)

```bash
cd /opt/security-system
source venv/bin/activate
python3 app.py
```

La aplicación estará disponible en: `http://tu-servidor:5000`

### Opción 2: Modo Producción (recomendado)

Instalar Gunicorn:

```bash
pip install gunicorn
```

Ejecutar con Gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Opción 3: Servicio Systemd (para que se inicie automáticamente)

Crear archivo de servicio:

```bash
sudo nano /etc/systemd/system/security-system.service
```

Contenido:

```ini
[Unit]
Description=Security System Web Panel
After=network.target

[Service]
Type=simple
User=tu-usuario
WorkingDirectory=/opt/security-system
Environment="PATH=/opt/security-system/venv/bin"
ExecStart=/opt/security-system/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Activar el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable security-system
sudo systemctl start security-system
sudo systemctl status security-system
```

## Paso 7: Configurar Nginx como Reverse Proxy (Recomendado)

Si ya tienes Nginx instalado:

```bash
sudo nano /etc/nginx/sites-available/security-system
```

Contenido:

```nginx
server {
    listen 80;
    server_name tu-dominio.com;  # O tu IP

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Activar:

```bash
sudo ln -s /etc/nginx/sites-available/security-system /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Paso 8: Configurar Firewall

Permitir acceso al puerto:

```bash
# Si usas UFW
sudo ufw allow 5000/tcp  # Solo si accedes directamente
sudo ufw allow 80/tcp    # Si usas Nginx
sudo ufw allow 443/tcp   # Si usas HTTPS
```

## Paso 9: Acceder al Sistema

Abre tu navegador y ve a:

```
http://tu-servidor-ip:5000
```

O si configuraste Nginx:

```
http://tu-dominio.com
```

Credenciales de login:
- Usuario: `admin` (o el que configuraste en .env)
- Contraseña: `Montero25` (o la que configuraste en .env)

## Configuración Inicial en el Panel Web

1. Accede a `/setup` o serás redirigido automáticamente
2. Configura las rutas:
   - Ruta de Odoo: `/opt/odoo` (o donde esté instalado)
   - Ruta de PostgreSQL: `/var/lib/postgresql`
   - Ruta de Nginx: `/etc/nginx`
   - Ruta de logs de Nginx: `/var/log/nginx`
   - Ruta de logs SSH: `/var/log/auth.log`

3. Selecciona componentes a instalar (si Fail2ban ya está instalado, se saltará)
4. Haz clic en "Iniciar Instalación"

## Verificación

Después de la configuración, verifica:

```bash
# Ver jails de Fail2ban
sudo fail2ban-client status

# Ver IPs bloqueadas
sudo fail2ban-client status sshd

# Ver logs recientes
sudo tail -f /var/log/fail2ban.log
```

## Troubleshooting

### Problema: "Fail2ban no está instalado"

```bash
# Verificar que fail2ban está corriendo
sudo systemctl status fail2ban

# Verificar ruta
which fail2ban-client

# Verificar permisos
ls -la /usr/bin/fail2ban-client
```

### Problema: "Permission denied"

```bash
# Verificar sudoers
sudo visudo -f /etc/sudoers.d/security-system

# Probar comando manualmente
sudo /usr/bin/fail2ban-client status
```

### Problema: No puede leer logs

```bash
# Verificar que existen los archivos
ls -la /var/log/fail2ban.log
ls -la /var/log/auth.log

# Dar permisos de lectura
sudo chmod +r /var/log/fail2ban.log
sudo chmod +r /var/log/auth.log
```

## Seguridad Adicional

1. **Cambiar puerto SSH** (recomendado):
   ```bash
   sudo nano /etc/ssh/sshd_config
   # Cambiar Port 22 a Port 2222
   sudo systemctl restart sshd
   ```

2. **Configurar HTTPS** con Let's Encrypt:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d tu-dominio.com
   ```

3. **Restringir acceso por IP** (si solo accedes desde IPs fijas):
   ```nginx
   # En /etc/nginx/sites-available/security-system
   location / {
       allow 123.456.789.0;  # Tu IP
       deny all;
       proxy_pass http://127.0.0.1:5000;
   }
   ```

## Mantenimiento

```bash
# Ver logs de la aplicación
sudo journalctl -u security-system -f

# Reiniciar aplicación
sudo systemctl restart security-system

# Actualizar código
cd /opt/security-system
git pull
sudo systemctl restart security-system
```
