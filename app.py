#!/usr/bin/env python3
"""
Sistema de Administración de Seguridad para Ubuntu Server
Autor: Security System
Descripción: Panel de control para gestionar la seguridad de servidores con Odoo, PostgreSQL y Nginx
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import json
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

# Importar módulos del sistema
from modules.config_manager import ConfigManager
from modules.firewall_manager import FirewallManager
from modules.fail2ban_manager import Fail2banManager
from modules.log_analyzer import LogAnalyzer
from modules.port_scanner import PortScanner
from modules.bot_detector import BotDetector
from modules.installer import SystemInstaller
from modules.threat_detector import ThreatDetector

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-this-secret-key')
CORS(app)

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'
login_manager.login_message_category = 'info'

# Modelo de Usuario
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Cargar usuario
@login_manager.user_loader
def load_user(user_id):
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    if user_id == '1':
        return User(1, admin_username)
    return None

# Inicializar managers
config_manager = ConfigManager()
firewall_manager = FirewallManager()
fail2ban_manager = Fail2banManager()
log_analyzer = LogAnalyzer()
port_scanner = PortScanner()
bot_detector = BotDetector()
installer = SystemInstaller()
threat_detector = ThreatDetector()


# ==================== AUTENTICACIÓN ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_password = os.getenv('ADMIN_PASSWORD', 'admin')

        if username == admin_username and password == admin_password:
            user = User(1, admin_username)
            login_user(user, remember=remember)

            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            return render_template('login.html', error='Usuario o contraseña incorrectos')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Cerrar sesión"""
    logout_user()
    return redirect(url_for('login'))


# ==================== RUTAS PRINCIPALES ====================

@app.route('/')
@login_required
def index():
    """Página principal - Dashboard"""
    config = config_manager.load_config()

    if not config.get('installed', False):
        return render_template('setup.html')

    return render_template('dashboard.html')


@app.route('/setup')
@login_required
def setup():
    """Página de configuración inicial"""
    return render_template('setup.html')


@app.route('/firewall')
@login_required
def firewall():
    """Página de gestión del firewall"""
    return render_template('firewall.html')


@app.route('/fail2ban')
@login_required
def fail2ban():
    """Página de gestión de Fail2ban"""
    return render_template('fail2ban.html')


@app.route('/logs')
@login_required
def logs():
    """Página de análisis de logs"""
    return render_template('logs.html')


@app.route('/threats')
@login_required
def threats():
    """Página de detección de amenazas"""
    return render_template('threats.html')


@app.route('/settings')
@login_required
def settings():
    """Página de configuración"""
    return render_template('settings.html')


# ==================== API ENDPOINTS ====================

# --- Configuración ---
@app.route('/api/config', methods=['GET'])
@login_required
def get_config():
    """Obtener configuración actual"""
    config = config_manager.load_config()
    return jsonify(config)


@app.route('/api/config', methods=['POST'])
@login_required
def save_config():
    """Guardar configuración"""
    data = request.json
    success = config_manager.save_config(data)
    return jsonify({'success': success})


@app.route('/api/install', methods=['POST'])
@login_required
def install_system():
    """Instalar componentes del sistema"""
    data = request.json
    result = installer.install_components(data)
    return jsonify(result)


# --- Dashboard ---
@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    """Obtener estadísticas del dashboard"""
    stats = {
        'blocked_ips': fail2ban_manager.get_blocked_ips_count(),
        'active_threats': threat_detector.get_active_threats_count(),
        'open_ports': port_scanner.get_open_ports_count(),
        'firewall_rules': firewall_manager.get_rules_count(),
        'failed_ssh_attempts': log_analyzer.get_failed_ssh_count(),
        'suspicious_requests': log_analyzer.get_suspicious_requests_count(),
        'detected_bots': bot_detector.get_detected_bots_count(),
    }
    return jsonify(stats)


@app.route('/api/dashboard/recent-activity', methods=['GET'])
def get_recent_activity():
    """Obtener actividad reciente"""
    activity = {
        'recent_blocks': fail2ban_manager.get_recent_blocks(limit=10),
        'recent_threats': threat_detector.get_recent_threats(limit=10),
        'recent_ssh_failures': log_analyzer.get_recent_ssh_failures(limit=10),
    }
    return jsonify(activity)


# --- Firewall ---
@app.route('/api/firewall/status', methods=['GET'])
def get_firewall_status():
    """Obtener estado del firewall"""
    status = firewall_manager.get_status()
    return jsonify(status)


@app.route('/api/firewall/rules', methods=['GET'])
def get_firewall_rules():
    """Obtener reglas del firewall"""
    rules = firewall_manager.get_rules()
    return jsonify({'rules': rules})


@app.route('/api/firewall/rule', methods=['POST'])
def add_firewall_rule():
    """Agregar regla al firewall"""
    data = request.json
    result = firewall_manager.add_rule(data)
    return jsonify(result)


@app.route('/api/firewall/rule/<int:rule_id>', methods=['DELETE'])
def delete_firewall_rule(rule_id):
    """Eliminar regla del firewall"""
    result = firewall_manager.delete_rule(rule_id)
    return jsonify(result)


@app.route('/api/firewall/toggle', methods=['POST'])
def toggle_firewall():
    """Activar/desactivar firewall"""
    data = request.json
    enable = data.get('enable', True)
    result = firewall_manager.toggle(enable)
    return jsonify(result)


# --- Fail2ban ---
@app.route('/api/fail2ban/status', methods=['GET'])
def get_fail2ban_status():
    """Obtener estado de Fail2ban"""
    status = fail2ban_manager.get_status()
    return jsonify(status)


@app.route('/api/fail2ban/jails', methods=['GET'])
def get_fail2ban_jails():
    """Obtener jails de Fail2ban"""
    jails = fail2ban_manager.get_jails()
    return jsonify({'jails': jails})


@app.route('/api/fail2ban/banned-ips', methods=['GET'])
def get_banned_ips():
    """Obtener IPs bloqueadas"""
    jail = request.args.get('jail', 'sshd')
    ips = fail2ban_manager.get_banned_ips(jail)
    return jsonify({'ips': ips})


@app.route('/api/fail2ban/unban', methods=['POST'])
def unban_ip():
    """Desbloquear IP"""
    data = request.json
    ip = data.get('ip')
    jail = data.get('jail', 'sshd')
    result = fail2ban_manager.unban_ip(ip, jail)
    return jsonify(result)


@app.route('/api/fail2ban/ban', methods=['POST'])
def ban_ip():
    """Bloquear IP manualmente"""
    data = request.json
    ip = data.get('ip')
    jail = data.get('jail', 'sshd')
    result = fail2ban_manager.ban_ip(ip, jail)
    return jsonify(result)


@app.route('/api/fail2ban/jail/toggle', methods=['POST'])
def toggle_jail():
    """Activar/desactivar jail"""
    data = request.json
    jail = data.get('jail')
    enable = data.get('enable', True)
    result = fail2ban_manager.toggle_jail(jail, enable)
    return jsonify(result)


@app.route('/api/fail2ban/jail/config', methods=['POST'])
@login_required
def update_jail_config():
    """Actualizar configuración de jail"""
    data = request.json
    jail = data.get('jail')
    config = data.get('config')
    result = fail2ban_manager.update_jail_config(jail, config)
    return jsonify(result)


@app.route('/api/fail2ban/jail/config/<jail_name>', methods=['GET'])
@login_required
def get_jail_config_api(jail_name):
    """Obtener configuración de una jail"""
    config = fail2ban_manager.get_jail_config(jail_name)
    if config:
        return jsonify({'success': True, 'config': config})
    return jsonify({'success': False, 'error': 'Jail no encontrada'})


@app.route('/api/fail2ban/create-rate-limit', methods=['POST'])
@login_required
def create_rate_limit_jail():
    """Crear jail para limitar peticiones HTTP (protección DDoS/flooding)"""
    data = request.json
    maxretry = data.get('maxretry', 100)
    findtime = data.get('findtime', 60)
    bantime = data.get('bantime', 3600)
    logpath = data.get('logpath', '/var/log/nginx/access.log')

    result = fail2ban_manager.create_nginx_rate_limit_jail(
        maxretry=maxretry,
        findtime=findtime,
        bantime=bantime,
        logpath=logpath
    )
    return jsonify(result)


@app.route('/api/fail2ban/create-bot-blocker', methods=['POST'])
@login_required
def create_bot_blocker_jail():
    """Crear jail para bloquear bots maliciosos"""
    data = request.json
    maxretry = data.get('maxretry', 50)
    findtime = data.get('findtime', 300)
    bantime = data.get('bantime', 7200)
    logpath = data.get('logpath', '/var/log/nginx/access.log')

    result = fail2ban_manager.create_bot_blocker_jail(
        maxretry=maxretry,
        findtime=findtime,
        bantime=bantime,
        logpath=logpath
    )
    return jsonify(result)


@app.route('/api/fail2ban/filters', methods=['GET'])
@login_required
def get_available_filters():
    """Obtener lista de filtros disponibles"""
    filters = fail2ban_manager.get_available_filters()
    return jsonify({'filters': filters})


# --- Logs ---
@app.route('/api/logs/ssh', methods=['GET'])
def get_ssh_logs():
    """Obtener logs de SSH"""
    limit = request.args.get('limit', 100, type=int)
    logs = log_analyzer.get_ssh_logs(limit)
    return jsonify({'logs': logs})


@app.route('/api/logs/nginx', methods=['GET'])
def get_nginx_logs():
    """Obtener logs de Nginx"""
    limit = request.args.get('limit', 100, type=int)
    log_type = request.args.get('type', 'access')
    logs = log_analyzer.get_nginx_logs(limit, log_type)
    return jsonify({'logs': logs})


@app.route('/api/logs/analyze', methods=['POST'])
def analyze_logs():
    """Analizar logs en busca de patrones sospechosos"""
    data = request.json
    log_type = data.get('type', 'all')
    analysis = log_analyzer.analyze_patterns(log_type)
    return jsonify(analysis)


# --- Detección de Amenazas ---
@app.route('/api/threats/scan', methods=['POST'])
def scan_threats():
    """Escanear en busca de amenazas"""
    result = threat_detector.scan()
    return jsonify(result)


@app.route('/api/threats/list', methods=['GET'])
def list_threats():
    """Listar amenazas detectadas"""
    threats = threat_detector.get_all_threats()
    return jsonify({'threats': threats})


@app.route('/api/threats/resolve', methods=['POST'])
def resolve_threat():
    """Marcar amenaza como resuelta"""
    data = request.json
    threat_id = data.get('threat_id')
    result = threat_detector.resolve_threat(threat_id)
    return jsonify(result)


# --- Detección de Bots ---
@app.route('/api/bots/detect', methods=['POST'])
def detect_bots():
    """Detectar bots en los logs"""
    result = bot_detector.analyze_logs()
    return jsonify(result)


@app.route('/api/bots/list', methods=['GET'])
def list_bots():
    """Listar bots detectados"""
    bots = bot_detector.get_detected_bots()
    return jsonify({'bots': bots})


@app.route('/api/bots/block', methods=['POST'])
def block_bot():
    """Bloquear bot detectado"""
    data = request.json
    ip = data.get('ip')
    result = bot_detector.block_bot(ip)
    return jsonify(result)


# --- Escaneo de Puertos ---
@app.route('/api/ports/scan', methods=['POST'])
def scan_ports():
    """Escanear puertos abiertos"""
    result = port_scanner.scan()
    return jsonify(result)


@app.route('/api/ports/list', methods=['GET'])
def list_ports():
    """Listar puertos abiertos"""
    ports = port_scanner.get_open_ports()
    return jsonify({'ports': ports})


# ==================== MANEJO DE ERRORES ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# ==================== INICIO DE LA APLICACIÓN ====================

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    debug = os.getenv('FLASK_ENV') == 'development'

    print(f"""
    ========================================================
    Sistema de Administracion de Seguridad para Ubuntu
    Servidor: {host}:{port}
    ========================================================
    """)

    app.run(host=host, port=port, debug=debug)
