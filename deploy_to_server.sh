#!/bin/bash
# Script de Despliegue del Sistema de Seguridad en Servidor Ubuntu
# Este script instala y configura todo automáticamente

set -e  # Detener si hay errores

echo "================================================================"
echo "  Sistema de Administración de Seguridad para Ubuntu"
echo "  Instalador Completo"
echo "================================================================"
echo ""

# Colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Este script debe ejecutarse como root${NC}"
    echo "Usa: sudo bash deploy_to_server.sh"
    exit 1
fi

# Obtener usuario real (no root)
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(eval echo ~$REAL_USER)

echo -e "${YELLOW}[1/10]${NC} Actualizando repositorios..."
apt-get update -qq

echo -e "${YELLOW}[2/10]${NC} Instalando dependencias del sistema..."
apt-get install -y python3 python3-pip python3-venv fail2ban ufw git curl -qq

echo -e "${YELLOW}[3/10]${NC} Configurando directorio de instalación..."
INSTALL_DIR="/opt/security-system"

if [ -d "$INSTALL_DIR" ]; then
    echo "Directorio $INSTALL_DIR ya existe. Creando backup..."
    mv "$INSTALL_DIR" "$INSTALL_DIR.backup.$(date +%Y%m%d%H%M%S)"
fi

mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
cd "$INSTALL_DIR"

echo -e "${YELLOW}[4/10]${NC} Creando entorno virtual Python..."
python3 -m venv venv
source venv/bin/activate

echo -e "${YELLOW}[5/10]${NC} Instalando dependencias Python..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

# Descomentar python-iptables para Linux
if grep -q "#.*python-iptables" requirements.txt; then
    sed -i 's/# python-iptables/python-iptables/' requirements.txt
    pip install python-iptables -q 2>/dev/null || echo "python-iptables skip (optional)"
fi

echo -e "${YELLOW}[6/10]${NC} Configurando variables de entorno..."
if [ ! -f .env ]; then
    cp .env.example .env

    # Generar SECRET_KEY aleatorio
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/your-secret-key-here-change-this/$SECRET_KEY/" .env

    echo ""
    echo -e "${GREEN}Configuración de credenciales:${NC}"
    read -p "Usuario admin [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}

    read -s -p "Contraseña admin [Montero25]: " ADMIN_PASS
    ADMIN_PASS=${ADMIN_PASS:-Montero25}
    echo ""

    sed -i "s/ADMIN_USERNAME=admin/ADMIN_USERNAME=$ADMIN_USER/" .env
    sed -i "s/ADMIN_PASSWORD=Montero25/ADMIN_PASSWORD=$ADMIN_PASS/" .env
fi

echo -e "${YELLOW}[7/10]${NC} Configurando permisos sudo para fail2ban..."
cat > /etc/sudoers.d/security-system << EOF
# Permisos para el Sistema de Seguridad
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl status fail2ban
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active fail2ban
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl start fail2ban
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl stop fail2ban
$REAL_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart fail2ban
$REAL_USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/fail2ban.log
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/auth.log
$REAL_USER ALL=(ALL) NOPASSWD: /usr/bin/tail -n * /var/log/nginx/*
EOF

chmod 0440 /etc/sudoers.d/security-system

echo -e "${YELLOW}[8/10]${NC} Creando servicio systemd..."
cat > /etc/systemd/system/security-system.service << EOF
[Unit]
Description=Security System Web Panel
After=network.target fail2ban.service

[Service]
Type=simple
User=$REAL_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable security-system

echo -e "${YELLOW}[9/10]${NC} Configurando firewall..."
# Obtener puerto SSH actual
SSH_PORT=$(ss -tlnp | grep sshd | grep -oP ':\K[0-9]+' | head -1)
SSH_PORT=${SSH_PORT:-22}

echo "Puerto SSH detectado: $SSH_PORT"

# Permitir SSH antes de habilitar firewall
ufw allow $SSH_PORT/tcp comment 'SSH'
ufw allow 5000/tcp comment 'Security System Web Panel'

echo -e "${YELLOW}[10/10]${NC} Instalando filtros de Fail2ban..."
# Ejecutar script de instalación de filtros si existe
if [ -f "install_fail2ban_filters.sh" ]; then
    bash install_fail2ban_filters.sh
else
    echo "Script de filtros no encontrado, saltando..."
fi

echo ""
echo "================================================================"
echo -e "${GREEN}¡Instalación completada exitosamente!${NC}"
echo "================================================================"
echo ""
echo "El sistema está instalado en: $INSTALL_DIR"
echo ""
echo "Para iniciar el servicio:"
echo "  sudo systemctl start security-system"
echo ""
echo "Para ver el estado:"
echo "  sudo systemctl status security-system"
echo ""
echo "Para ver los logs:"
echo "  sudo journalctl -u security-system -f"
echo ""
echo -e "${GREEN}Acceso al panel web:${NC}"
echo "  http://$(hostname -I | awk '{print $1}'):5000"
echo "  http://$(curl -s ifconfig.me 2>/dev/null || echo 'TU-IP-PUBLICA'):5000"
echo ""
echo -e "${YELLOW}Credenciales de acceso:${NC}"
echo "  Usuario: $ADMIN_USER"
echo "  Contraseña: [la que configuraste]"
echo ""
echo -e "${RED}IMPORTANTE:${NC}"
echo "  1. Cambia las credenciales en producción"
echo "  2. Considera usar HTTPS (con Nginx + Let's Encrypt)"
echo "  3. El firewall permitirá automáticamente el puerto 5000"
echo ""
echo "¿Deseas iniciar el servicio ahora? (s/n)"
read -r START_NOW

if [ "$START_NOW" = "s" ] || [ "$START_NOW" = "S" ]; then
    systemctl start security-system
    sleep 2

    if systemctl is-active --quiet security-system; then
        echo -e "${GREEN}✓ Servicio iniciado correctamente${NC}"
        echo ""
        echo "Puedes acceder ahora en:"
        echo "  http://$(hostname -I | awk '{print $1}'):5000"
    else
        echo -e "${RED}✗ Error al iniciar el servicio${NC}"
        echo "Ver logs: sudo journalctl -u security-system -n 50"
    fi
fi

echo ""
echo "================================================================"
