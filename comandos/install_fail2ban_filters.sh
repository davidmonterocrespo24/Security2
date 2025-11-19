#!/bin/bash
# Script para instalar filtros y jails de Fail2ban
# Ejecutar con: sudo bash install_fail2ban_filters.sh

echo "============================================"
echo "Instalador de Filtros Fail2ban"
echo "Sistema de Seguridad para Ubuntu"
echo "============================================"
echo ""

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Este script debe ejecutarse como root (usa sudo)"
    exit 1
fi

# Verificar que fail2ban está instalado
if ! command -v fail2ban-client &> /dev/null; then
    echo "ERROR: Fail2ban no está instalado"
    echo "Instálalo con: sudo apt install fail2ban -y"
    exit 1
fi

echo "[1/5] Verificando directorios..."
if [ ! -d "/etc/fail2ban/filter.d" ]; then
    echo "ERROR: Directorio /etc/fail2ban/filter.d no existe"
    exit 1
fi

if [ ! -d "/etc/fail2ban/jail.d" ]; then
    echo "ERROR: Directorio /etc/fail2ban/jail.d no existe"
    exit 1
fi

echo "[2/5] Creando backup de configuración actual..."
BACKUP_DIR="/etc/fail2ban/backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /etc/fail2ban/filter.d/nginx-req-limit*.conf "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/fail2ban/jail.d/nginx-req-limit*.local "$BACKUP_DIR/" 2>/dev/null || true
echo "Backup creado en: $BACKUP_DIR"

echo "[3/5] Instalando filtros..."

# Filtro agresivo para detección de peticiones
cat > /etc/fail2ban/filter.d/nginx-req-limit-aggressive.conf << 'EOF'
# Fail2ban filter AGRESIVO para bloquear ataques DDoS/flooding

[Definition]
failregex = ^<HOST> -.*"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS).*HTTP.*"
ignoreregex =

[Init]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
EOF

echo "✓ Filtro nginx-req-limit-aggressive.conf instalado"

# Filtro para errores 4xx y 5xx
cat > /etc/fail2ban/filter.d/nginx-req-limit.conf << 'EOF'
# Fail2ban filter para limitar peticiones HTTP con errores

[Definition]
failregex = ^<HOST> -.*"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS).*HTTP.*" (4\d\d|5\d\d)
ignoreregex =
EOF

echo "✓ Filtro nginx-req-limit.conf instalado"

echo "[4/5] Instalando jails..."

# Detectar ruta de logs de Nginx
NGINX_LOG="/var/log/nginx/access.log"
if [ ! -f "$NGINX_LOG" ]; then
    echo "⚠ WARNING: $NGINX_LOG no encontrado"
    echo "   Buscando logs de Nginx..."

    # Buscar logs de Nginx en ubicaciones comunes
    if [ -f "/var/log/nginx/access_log" ]; then
        NGINX_LOG="/var/log/nginx/access_log"
    elif [ -f "/opt/odoo/nginx/logs/access.log" ]; then
        NGINX_LOG="/opt/odoo/nginx/logs/access.log"
    else
        echo "   No se encontró log de Nginx. Usando ruta por defecto."
        NGINX_LOG="/var/log/nginx/access.log"
    fi
fi

echo "   Usando log: $NGINX_LOG"

# Jail configuración balanceada (100 req en 60 seg)
cat > /etc/fail2ban/jail.d/nginx-req-limit.local << EOF
# Jail para bloquear IPs con demasiadas peticiones HTTP
# Configuración BALANCEADA

[nginx-req-limit]
enabled = true
port = http,https
filter = nginx-req-limit-aggressive
logpath = $NGINX_LOG
maxretry = 100
findtime = 60
bantime = 3600
action = %(action_mwl)s
EOF

echo "✓ Jail nginx-req-limit.local instalado (100 req/60seg)"

# Jail super agresivo (deshabilitado por defecto)
cat > /etc/fail2ban/jail.d/nginx-req-limit-super.local << EOF
# Jail SUPER AGRESIVO (deshabilitado por defecto)
# Para activar: cambiar enabled = false a enabled = true

[nginx-req-limit-super]
enabled = false
port = http,https
filter = nginx-req-limit-aggressive
logpath = $NGINX_LOG
maxretry = 30
findtime = 10
bantime = 14400
action = %(action_mwl)s
EOF

echo "✓ Jail nginx-req-limit-super.local instalado (DESHABILITADO)"

echo "[5/5] Reiniciando Fail2ban..."
systemctl restart fail2ban

# Esperar a que fail2ban inicie
sleep 2

# Verificar estado
if systemctl is-active --quiet fail2ban; then
    echo "✓ Fail2ban reiniciado correctamente"
else
    echo "✗ ERROR: Fail2ban no está corriendo"
    echo "Verifica los logs: sudo journalctl -u fail2ban -n 50"
    exit 1
fi

echo ""
echo "============================================"
echo "¡Instalación completada exitosamente!"
echo "============================================"
echo ""
echo "Comandos útiles:"
echo ""
echo "  # Ver estado de todas las jails:"
echo "  sudo fail2ban-client status"
echo ""
echo "  # Ver estado de la jail nginx-req-limit:"
echo "  sudo fail2ban-client status nginx-req-limit"
echo ""
echo "  # Ver IPs bloqueadas:"
echo "  sudo fail2ban-client status nginx-req-limit | grep 'Banned IP'"
echo ""
echo "  # Desbloquear una IP:"
echo "  sudo fail2ban-client set nginx-req-limit unbanip IP_ADDRESS"
echo ""
echo "  # Ver logs de fail2ban:"
echo "  sudo tail -f /var/log/fail2ban.log"
echo ""
echo "  # Activar jail super agresivo:"
echo "  sudo nano /etc/fail2ban/jail.d/nginx-req-limit-super.local"
echo "  # Cambiar 'enabled = false' a 'enabled = true'"
echo "  sudo systemctl restart fail2ban"
echo ""
echo "Configuración actual:"
echo "  - Jail: nginx-req-limit"
echo "  - Máximo: 100 peticiones en 60 segundos"
echo "  - Tiempo de ban: 3600 segundos (1 hora)"
echo "  - Log monitoreado: $NGINX_LOG"
echo ""
