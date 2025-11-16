# Sistema de Administración de Seguridad para Ubuntu Server

![Security System](https://img.shields.io/badge/Security-System-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey)
![License](https://img.shields.io/badge/License-MIT-yellow)

Sistema completo de administración y monitoreo de seguridad para servidores Ubuntu con Odoo, PostgreSQL y Nginx. Incluye protección contra ataques de fuerza bruta, detección de bots, análisis de logs, gestión de firewall y más.

## Características Principales

### 🛡️ Protección Integral
- **Fail2ban**: Protección automática contra ataques de fuerza bruta
- **Firewall (UFW)**: Gestión visual del firewall de Ubuntu
- **Detección de Bots**: Identificación y bloqueo de scrapers maliciosos
- **Análisis de Amenazas**: Detección de SQL injection, XSS, escaneos de vulnerabilidades

### 📊 Monitoreo en Tiempo Real
- Dashboard con estadísticas en vivo
- Análisis de logs SSH y Nginx
- Escaneo de puertos abiertos
- Actividad sospechosa en tiempo real

### ⚙️ Configuración Visual
- Interfaz web moderna con Tailwind CSS
- Configuración de rutas del sistema
- Gestión de IPs bloqueadas
- Configuración de jails de Fail2ban

### 🔍 Análisis Avanzado
- Detección de patrones de ataque
- Análisis de User-Agents
- Identificación de comportamiento anómalo
- Reportes de seguridad

## Requisitos del Sistema

- **Sistema Operativo**: Ubuntu 18.04 o superior
- **Python**: 3.8 o superior
- **Privilegios**: Acceso root/sudo
- **Servicios**: Nginx, PostgreSQL (opcional), Odoo (opcional)

## ⚠️ ADVERTENCIA DE SEGURIDAD IMPORTANTE

**CRÍTICO - Firewall y SSH**: Al activar el firewall, existe el riesgo de quedarte bloqueado fuera del servidor.

### Protecciones Automáticas Incluidas

Este sistema incluye **múltiples capas de protección** para prevenir el bloqueo:

1. **El sistema automáticamente permite SSH (puerto 22)** antes de activar UFW
2. **Verifica que la regla fue creada** antes de activar el firewall
3. **Si no puede permitir SSH, NO activa el firewall** por seguridad

### Si Usas Puerto SSH Personalizado

**IMPORTANTE**: Si tu SSH NO está en el puerto 22:

```bash
# ANTES de activar el firewall, permite tu puerto SSH personalizado
sudo ufw allow TU_PUERTO/tcp

# Ejemplo para puerto 2222:
sudo ufw allow 2222/tcp
```

### Recomendaciones Antes de Activar el Firewall

- ✅ Verifica tu puerto SSH: `sudo netstat -tlnp | grep ssh`
- ✅ Asegúrate de tener acceso alternativo (consola física, KVM)
- ✅ Lee [SECURITY.md](SECURITY.md) para más detalles

**Ver guía completa**: [Guía de Seguridad (SECURITY.md)](SECURITY.md)

## Instalación Rápida

### Método 1: Script Automático

```bash
# Dar permisos de ejecución al instalador
chmod +x install.sh

# Ejecutar instalador
sudo ./install.sh
```

El script automático instalará:
- Dependencias del sistema
- Python y entorno virtual
- Fail2ban
- UFW (Firewall)
- Servicio systemd

### Método 2: Instalación Manual

```bash
# 1. Instalar dependencias del sistema
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv ufw fail2ban

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias de Python
pip install -r requirements.txt

# 4. Configurar archivo .env
cp .env.example .env
nano .env

# 5. Ejecutar aplicación
python app.py
```

## Configuración Inicial

### 1. Acceder a la Interfaz Web

Después de la instalación, accede a:
```
http://tu-servidor:5000
```

### 2. Configuración de Rutas

En el primer inicio, deberás configurar las rutas de tus servicios:

- **Odoo**: Ruta de instalación de Odoo (ej: `/opt/odoo`)
- **PostgreSQL**: Ruta de datos de PostgreSQL (ej: `/var/lib/postgresql`)
- **Nginx**: Ruta de configuración (ej: `/etc/nginx`)
- **Logs Nginx**: Ruta de logs (ej: `/var/log/nginx`)
- **Logs SSH**: Archivo de logs (ej: `/var/log/auth.log`)

### 3. Instalación de Componentes

Selecciona los componentes a instalar:
- ✅ Fail2ban
- ✅ UFW (Firewall)
- ✅ Protección Nginx
- ✅ Protección SSH

## Uso del Sistema

### Dashboard

El dashboard muestra:
- Cantidad de IPs bloqueadas
- Amenazas activas detectadas
- Puertos abiertos en el sistema
- Reglas de firewall configuradas
- Actividad reciente
- Bloqueos recientes

### Gestión de Firewall

**Acciones disponibles:**
- Ver estado del firewall
- Activar/desactivar UFW
- Agregar reglas personalizadas
- Eliminar reglas existentes
- Accesos rápidos (SSH, HTTP, HTTPS, PostgreSQL)

**Agregar una regla:**
```
Acción: ALLOW
Puerto: 8069
Protocolo: TCP
IP Origen: any (o específica)
```

### Gestión de Fail2ban

**Funcionalidades:**
- Ver estado de jails activas
- IPs bloqueadas por jail
- Bloquear IPs manualmente
- Desbloquear IPs
- Activar/desactivar jails

**Jails configuradas:**
- `sshd`: Protección SSH
- `nginx-req-limit`: Límite de peticiones HTTP
- `http-bot-blocker`: Bloqueo de bots maliciosos

### Análisis de Logs

**Logs disponibles:**
- **SSH**: Intentos de autenticación, usuarios, IPs
- **Nginx**: Accesos, métodos HTTP, códigos de estado

**Análisis de patrones:**
- Top IPs atacantes
- Intentos fallidos por usuario
- Peticiones sospechosas
- Códigos de error HTTP

### Detección de Amenazas

El sistema detecta automáticamente:
- **Ataques de fuerza bruta**: Múltiples intentos fallidos de login
- **Scraping agresivo**: IPs con exceso de peticiones
- **Escaneo de vulnerabilidades**: Intentos de acceso a archivos sensibles
- **SQL Injection**: Patrones de inyección SQL en URLs
- **XSS**: Intentos de cross-site scripting
- **Bots maliciosos**: User-agents sospechosos

## Arquitectura del Sistema

```
security-system/
├── app.py                 # Aplicación Flask principal
├── config.json           # Configuración del sistema
├── requirements.txt      # Dependencias Python
├── install.sh           # Script de instalación
├── modules/             # Módulos del sistema
│   ├── config_manager.py
│   ├── firewall_manager.py
│   ├── fail2ban_manager.py
│   ├── log_analyzer.py
│   ├── bot_detector.py
│   ├── port_scanner.py
│   ├── threat_detector.py
│   └── installer.py
├── templates/           # Plantillas HTML
│   ├── base.html
│   ├── dashboard.html
│   ├── firewall.html
│   ├── fail2ban.html
│   ├── logs.html
│   ├── threats.html
│   ├── settings.html
│   └── setup.html
└── static/             # Archivos estáticos
    ├── css/
    └── js/
```

## Comandos Útiles

### Gestión del Servicio

```bash
# Ver estado
sudo systemctl status security-system

# Iniciar
sudo systemctl start security-system

# Detener
sudo systemctl stop security-system

# Reiniciar
sudo systemctl restart security-system

# Ver logs
sudo journalctl -u security-system -f
```

### Fail2ban

```bash
# Estado general
sudo fail2ban-client status

# Estado de jail específica
sudo fail2ban-client status sshd

# Desbloquear IP manualmente
sudo fail2ban-client set sshd unbanip 192.168.1.100
```

### UFW

```bash
# Ver estado
sudo ufw status verbose

# Ver reglas numeradas
sudo ufw status numbered

# Eliminar regla
sudo ufw delete [número]
```

## Licencia

Este proyecto está bajo la Licencia MIT.

---

**Nota**: Este sistema está diseñado específicamente para protección defensiva. No debe ser utilizado para actividades maliciosas.
