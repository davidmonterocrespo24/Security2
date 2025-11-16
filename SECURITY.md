# Guía de Seguridad del Sistema

## ⚠️ Advertencias Importantes

### Firewall y Acceso SSH

**CRÍTICO**: Al activar el firewall, existe el riesgo de quedarte bloqueado fuera del servidor.

#### Protecciones Implementadas

Este sistema incluye **protecciones automáticas** para prevenir el bloqueo:

1. **Al activar UFW**, el sistema automáticamente:
   - Permite SSH en el puerto 22 **ANTES** de activar el firewall
   - Verifica que la regla SSH fue creada correctamente
   - Si no puede permitir SSH, **NO activa el firewall**

2. **Advertencias visuales** en la interfaz web:
   - Banner de advertencia en la página de Firewall
   - Confirmación detallada antes de activar
   - Mensaje de éxito confirmando que SSH está permitido

3. **Script de instalación seguro**:
   - Permite SSH antes de habilitar UFW
   - Verifica que la regla fue aplicada
   - Muestra claramente los puertos permitidos

#### Si Usas Puerto SSH Personalizado

**IMPORTANTE**: Si cambiaste el puerto SSH del 22 a otro (ej: 2222):

```bash
# Opción 1: Desde línea de comandos (ANTES de activar UFW)
sudo ufw allow 2222/tcp

# Opción 2: Desde la interfaz web
1. Ir a la página "Firewall"
2. Agregar regla:
   - Acción: ALLOW
   - Puerto: 2222
   - Protocolo: TCP
3. Luego activar el firewall
```

#### Recuperación en Caso de Bloqueo

Si quedaste bloqueado, **necesitarás acceso físico o consola del servidor**:

```bash
# Opción 1: Desactivar UFW
sudo ufw disable

# Opción 2: Permitir tu IP específica
sudo ufw allow from TU_IP to any port 22

# Opción 3: Resetear UFW completamente
sudo ufw reset
```

## Mejores Prácticas

### 1. Antes de Activar el Firewall

- [ ] Verifica cuál es tu puerto SSH actual: `sudo netstat -tlnp | grep ssh`
- [ ] Si NO es el 22, agrégalo primero a las reglas
- [ ] Asegúrate de tener acceso alternativo (consola física, KVM, etc.)
- [ ] Anota tu IP actual para permitirla si es necesario

### 2. Al Configurar Reglas

- [ ] **SSH siempre permitido**: Nunca elimines la regla de SSH
- [ ] **HTTP/HTTPS**: Necesarios si ejecutas un servidor web
- [ ] **PostgreSQL (5432)**: Solo si accedes remotamente a la BD
- [ ] **Odoo (8069)**: Solo si no usas proxy reverso

### 3. Seguridad del Sistema

#### Cambiar SECRET_KEY

Edita el archivo `/opt/security-system/.env`:

```bash
sudo nano /opt/security-system/.env

# Cambia esta línea a un valor único:
SECRET_KEY=tu-clave-secreta-unica-aqui
```

Genera una clave segura:

```bash
openssl rand -hex 32
```

#### Configurar HTTPS con Nginx

```nginx
# /etc/nginx/sites-available/security-system
server {
    listen 443 ssl http2;
    server_name security.tudominio.com;

    ssl_certificate /etc/letsencrypt/live/tudominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tudominio.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name security.tudominio.com;
    return 301 https://$server_name$request_uri;
}
```

Obtener certificado SSL:

```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d security.tudominio.com
```

#### Restringir Acceso por IP

Si solo accedes desde IPs específicas:

```bash
# Permitir solo tu IP
sudo ufw allow from TU_IP to any port 5000

# Denegar todas las demás
sudo ufw deny 5000/tcp
```

O en Nginx:

```nginx
location / {
    allow 192.168.1.100;
    deny all;
    proxy_pass http://127.0.0.1:5000;
}
```

### 4. Fail2ban - Precauciones

#### No Bloquearte a Ti Mismo

Agrega tu IP a la lista blanca de Fail2ban:

```bash
# /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 TU_IP_AQUI
```

Reinicia Fail2ban:

```bash
sudo systemctl restart fail2ban
```

#### Si Te Bloquea Fail2ban

```bash
# Ver si estás bloqueado
sudo fail2ban-client status sshd

# Desbloquearte
sudo fail2ban-client set sshd unbanip TU_IP
```

### 5. Monitoreo y Logs

#### Ver logs del sistema

```bash
# Logs del sistema de seguridad
sudo journalctl -u security-system -f

# Logs de UFW
sudo tail -f /var/log/ufw.log

# Logs de Fail2ban
sudo tail -f /var/log/fail2ban.log

# Logs de SSH
sudo tail -f /var/log/auth.log
```

#### Verificar reglas activas

```bash
# Ver reglas UFW
sudo ufw status numbered

# Ver IPs bloqueadas por Fail2ban
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Ver conexiones activas
sudo netstat -tunap
```

## Lista de Verificación de Seguridad

Antes de poner en producción:

- [ ] SECRET_KEY cambiada
- [ ] HTTPS configurado
- [ ] Puerto SSH verificado y permitido
- [ ] Acceso de respaldo disponible (consola física/KVM)
- [ ] Tu IP en whitelist de Fail2ban
- [ ] Reglas de firewall revisadas
- [ ] Backups configurados
- [ ] Logs funcionando correctamente
- [ ] Autenticación adicional (opcional)
- [ ] Monitoreo configurado

## Soporte de Emergencia

### Si Pierdes Acceso SSH

1. **Acceso por consola física o KVM**
2. Login como root
3. Ejecutar: `sudo ufw disable`
4. Verificar puerto SSH: `sudo netstat -tlnp | grep ssh`
5. Permitir puerto correcto: `sudo ufw allow PUERTO/tcp`
6. Reactivar: `sudo ufw enable`

### Si Fail2ban Te Bloquea

1. Acceso por consola
2. Ver IPs bloqueadas: `sudo fail2ban-client status sshd`
3. Desbloquear: `sudo fail2ban-client set sshd unbanip TU_IP`
4. Agregar a whitelist permanente en `/etc/fail2ban/jail.local`

### Contacto

Para reportar problemas de seguridad, abre un issue en GitHub marcado como "security".

---

**Recuerda**: La seguridad es un proceso continuo. Mantén el sistema actualizado y revisa los logs regularmente.
