#!/bin/bash

# setup_service.sh
# Configura la aplicación Flask como un servicio systemd en Ubuntu/Debian
# Uso: ./comandos/setup_service.sh (desde la raíz del proyecto)

# Nombre del servicio
SERVICE_NAME="security-monitor"

# Obtener directorio actual
# Si el script se ejecuta desde la carpeta 'comandos', subir un nivel
if [[ $(basename $(pwd)) == "comandos" ]]; then
    cd ..
fi

PROJECT_DIR=$(pwd)
USER_NAME=$(whoami)
GROUP_NAME=$(id -gn)

# Detectar Python (captura el python del entorno virtual si está activo, o el del sistema)
PYTHON_BIN=$(which python3)

echo "===================================================="
echo "Configurando servicio systemd: $SERVICE_NAME"
echo "===================================================="
echo "Directorio del proyecto: $PROJECT_DIR"
echo "Usuario de ejecución:    $USER_NAME"
echo "Ejecutable Python:       $PYTHON_BIN"
echo "===================================================="

# Verificar que app.py existe
if [ ! -f "$PROJECT_DIR/app.py" ]; then
    echo "ERROR: No se encuentra app.py en $PROJECT_DIR"
    echo "Por favor ejecuta este script desde la raíz del proyecto."
    exit 1
fi

# Definir contenido del archivo .service
# Se asume que si existe un venv, está en el directorio del proyecto, pero usamos el python detectado
SERVICE_FILE_CONTENT="[Unit]
Description=Security Monitor System Web Panel
After=network.target postgresql.service

[Service]
User=$USER_NAME
Group=$GROUP_NAME
WorkingDirectory=$PROJECT_DIR
# Configurar variables de entorno si es necesario
Environment=\"PATH=$(dirname $PYTHON_BIN):/usr/local/bin:/usr/bin:/bin\"
ExecStart=$PYTHON_BIN app.py
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target"

# Crear el archivo de servicio en /etc/systemd/system/
echo "Creando archivo /etc/systemd/system/$SERVICE_NAME.service..."
# Usamos sudo bash -c para escribir el archivo con permisos de root
sudo bash -c "cat > /etc/systemd/system/$SERVICE_NAME.service" <<EOF
$SERVICE_FILE_CONTENT
EOF

# Recargar configuración de systemd
echo "Recargando demonio systemd..."
sudo systemctl daemon-reload

# Habilitar el servicio para que inicie en el arranque
echo "Habilitando el servicio para inicio automático..."
sudo systemctl enable $SERVICE_NAME

# Iniciar (o reiniciar) el servicio ahora
echo "Iniciando el servicio..."
sudo systemctl restart $SERVICE_NAME

# Mostrar estado
echo "Verificando estado..."
sudo systemctl status $SERVICE_NAME --no-pager

echo "===================================================="
echo "Instalación completada con éxito."
echo "La aplicación ahora se iniciará automáticamente al encender el servidor."
echo ""
echo "Comandos útiles:"
echo "  Ver logs en tiempo real: sudo journalctl -u $SERVICE_NAME -f"
echo "  Detener servicio:        sudo systemctl stop $SERVICE_NAME"
echo "  Iniciar servicio:        sudo systemctl start $SERVICE_NAME"
echo "  Reiniciar servicio:      sudo systemctl restart $SERVICE_NAME"
echo "===================================================="
