#!/bin/bash

# Script de Instalación del Sistema de Seguridad para Ubuntu
# Autor: Security System

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funciones de utilidad
print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Sistema de Administración de Seguridad para Ubuntu      ║"
    echo "║  Instalador Automático                                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Verificar que se ejecuta como root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Este script debe ejecutarse como root o con sudo"
        exit 1
    fi
    print_success "Verificación de permisos correcta"
}

# Verificar sistema operativo
check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            print_warning "Este script está diseñado para Ubuntu. Continuar bajo su propio riesgo."
            read -p "¿Desea continuar? (s/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Ss]$ ]]; then
                exit 1
            fi
        else
            print_success "Sistema operativo compatible: Ubuntu $VERSION_ID"
        fi
    fi
}

# Actualizar sistema
update_system() {
    print_info "Actualizando paquetes del sistema..."
    apt-get update -qq
    print_success "Sistema actualizado"
}

# Instalar dependencias del sistema
install_system_deps() {
    print_info "Instalando dependencias del sistema..."

    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        ufw \
        fail2ban \
        net-tools \
        iptables \
        > /dev/null 2>&1

    print_success "Dependencias instaladas"
}

# Crear entorno virtual de Python
setup_python_env() {
    print_info "Configurando entorno virtual de Python..."

    INSTALL_DIR="/opt/security-system"

    if [ ! -d "$INSTALL_DIR" ]; then
        mkdir -p "$INSTALL_DIR"
    fi

    cd "$INSTALL_DIR"

    # Copiar archivos del proyecto
    if [ -d "/tmp/security-system" ]; then
        cp -r /tmp/security-system/* "$INSTALL_DIR/"
    fi

    # Crear entorno virtual
    python3 -m venv venv
    source venv/bin/activate

    # Instalar dependencias de Python
    pip install -q --upgrade pip
    pip install -q -r requirements.txt

    print_success "Entorno Python configurado"
}

# Configurar Fail2ban
setup_fail2ban() {
    print_info "Configurando Fail2ban..."

    # Habilitar y arrancar fail2ban
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl start fail2ban > /dev/null 2>&1

    # Crear configuración para SSH
    cat > /etc/fail2ban/jail.d/sshd.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
EOF

    # Crear configuración para Nginx
    cat > /etc/fail2ban/filter.d/nginx-req-limit.conf << EOF
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*" (4|5)\d{2}
ignoreregex =
EOF

    cat > /etc/fail2ban/jail.d/nginx-req-limit.local << EOF
[nginx-req-limit]
enabled = true
port = http,https
filter = nginx-req-limit
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime = 3600
EOF

    # Crear filtro para bots
    cat > /etc/fail2ban/filter.d/http-bot-blocker.conf << EOF
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*".*"(bot|crawler|spider|scraper|curl|wget|python-requests|axios).*"
ignoreregex = (Googlebot|bingbot|YandexBot|DuckDuckBot)
EOF

    cat > /etc/fail2ban/jail.d/http-bot-blocker.local << EOF
[http-bot-blocker]
enabled = true
port = http,https
filter = http-bot-blocker
logpath = /var/log/nginx/access.log
maxretry = 50
findtime = 300
bantime = 7200
EOF

    # Reiniciar fail2ban
    systemctl restart fail2ban

    print_success "Fail2ban configurado"
}

# Configurar UFW
setup_ufw() {
    print_info "Configurando UFW (Firewall)..."

    # Configurar reglas básicas
    ufw --force reset > /dev/null 2>&1

    # Permitir SSH para no perder conexión
    ufw allow ssh > /dev/null 2>&1
    ufw allow 22/tcp > /dev/null 2>&1

    # Permitir HTTP y HTTPS
    ufw allow http > /dev/null 2>&1
    ufw allow https > /dev/null 2>&1

    # Habilitar UFW
    echo "y" | ufw enable > /dev/null 2>&1

    print_success "UFW configurado"
}

# Crear servicio systemd
create_systemd_service() {
    print_info "Creando servicio systemd..."

    cat > /etc/systemd/system/security-system.service << EOF
[Unit]
Description=Sistema de Administración de Seguridad
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/security-system
Environment="PATH=/opt/security-system/venv/bin"
ExecStart=/opt/security-system/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Recargar systemd
    systemctl daemon-reload

    # Habilitar servicio
    systemctl enable security-system > /dev/null 2>&1

    print_success "Servicio systemd creado"
}

# Configurar archivo .env
setup_env_file() {
    print_info "Configurando archivo de entorno..."

    if [ ! -f "/opt/security-system/.env" ]; then
        cat > /opt/security-system/.env << EOF
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=$(openssl rand -hex 32)
PORT=5000
HOST=0.0.0.0
EOF
    fi

    print_success "Archivo .env configurado"
}

# Configurar permisos
setup_permissions() {
    print_info "Configurando permisos..."

    chmod +x /opt/security-system/app.py
    chown -R root:root /opt/security-system

    print_success "Permisos configurados"
}

# Iniciar servicio
start_service() {
    print_info "Iniciando servicio..."

    systemctl start security-system

    sleep 2

    if systemctl is-active --quiet security-system; then
        print_success "Servicio iniciado correctamente"
    else
        print_error "Error al iniciar el servicio"
        systemctl status security-system
    fi
}

# Mostrar información final
show_final_info() {
    echo ""
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Instalación Completada Exitosamente                     ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo ""
    print_info "El sistema está disponible en: http://$(hostname -I | awk '{print $1}'):5000"
    echo ""
    print_info "Comandos útiles:"
    echo "  - Ver estado: systemctl status security-system"
    echo "  - Ver logs: journalctl -u security-system -f"
    echo "  - Reiniciar: systemctl restart security-system"
    echo "  - Detener: systemctl stop security-system"
    echo ""
    print_warning "Por seguridad, se recomienda:"
    echo "  1. Cambiar la SECRET_KEY en /opt/security-system/.env"
    echo "  2. Configurar un proxy reverso (Nginx) con HTTPS"
    echo "  3. Configurar autenticación adicional si es necesario"
    echo ""
}

# Función principal
main() {
    print_header

    print_info "Iniciando instalación..."
    echo ""

    check_root
    check_os
    update_system
    install_system_deps
    setup_python_env
    setup_fail2ban
    setup_ufw
    create_systemd_service
    setup_env_file
    setup_permissions
    start_service

    show_final_info
}

# Ejecutar instalación
main
