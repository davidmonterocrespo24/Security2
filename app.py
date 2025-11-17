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
from modules.attack_detector import AttackDetector
from modules.geo_intelligence import GeoIntelligence

# Importar módulos de base de datos
from database.db_manager import DatabaseManager
from database.models import init_database

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

# Inicializar base de datos
init_database()

# Inicializar managers
config_manager = ConfigManager()
db_manager = DatabaseManager()
firewall_manager = FirewallManager()
fail2ban_manager = Fail2banManager()
port_scanner = PortScanner()
bot_detector = BotDetector()
installer = SystemInstaller()
threat_detector = ThreatDetector()

# Inicializar módulos de seguridad avanzada
attack_detector = AttackDetector(db_manager)
geo_intelligence = GeoIntelligence(db_manager)
log_analyzer = LogAnalyzer(db_manager, attack_detector)

# Inicializar detector ML
from modules.ml_detector import MLTrafficDetector
ml_detector = MLTrafficDetector(db_manager)

# Inicializar servicio de geolocalización
from modules.geo_service import GeoLocationService
geo_service = GeoLocationService(db_manager)


# ==================== MIDDLEWARE DE SEGURIDAD ====================

@app.before_request
def security_middleware():
    """Middleware para analizar todas las peticiones en busca de amenazas"""
    # Excluir rutas estáticas
    if request.path.startswith('/static/'):
        return None

    # Obtener IP del cliente
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    else:
        client_ip = request.remote_addr or 'unknown'

    # Verificar si la IP está en whitelist
    if db_manager.is_ip_whitelisted(client_ip):
        return None

    # Verificar si la IP está bloqueada
    if db_manager.is_ip_blocked(client_ip):
        db_manager.log_security_event(
            event_type='blocked_access_attempt',
            severity='medium',
            source_ip=client_ip,
            attack_vector='blocked_ip',
            description=f'Intento de acceso desde IP bloqueada: {client_ip}',
            request_path=request.path
        )
        return jsonify({'error': 'Access denied', 'message': 'Your IP has been blocked'}), 403

    # Analizar petición HTTP en busca de ataques
    user_agent = request.headers.get('User-Agent', '')
    method = request.method
    path = request.path

    analysis = attack_detector.analyze_http_request(client_ip, method, path, user_agent)

    if analysis['is_threat']:
        # Registrar evento de seguridad
        db_manager.log_security_event(
            event_type='attack_detected',
            severity=analysis['severity'],
            source_ip=client_ip,
            attack_vector=analysis.get('attack_type', 'unknown'),
            description=analysis.get('description', 'Suspicious request detected'),
            request_method=method,
            request_path=path,
            user_agent=user_agent,
            details=json.dumps(analysis.get('details', {}))
        )

        # Bloqueo automático para amenazas críticas
        if analysis['should_block']:
            db_manager.block_ip(
                ip_address=client_ip,
                reason=f"Auto-blocked: {analysis.get('attack_type', 'threat')}",
                blocked_by='auto',
                duration_hours=24
            )

            db_manager.create_alert(
                alert_type='auto_block',
                severity='high',
                title=f'IP bloqueada automáticamente: {client_ip}',
                message=f"Tipo de ataque: {analysis.get('attack_type', 'unknown')}",
                source_ip=client_ip
            )

            return jsonify({'error': 'Access denied', 'message': 'Suspicious activity detected'}), 403

        # Crear alerta para amenazas que requieren revisión manual
        elif analysis['severity'] in ['medium', 'high']:
            db_manager.create_alert(
                alert_type='suspicious_activity',
                severity=analysis['severity'],
                title=f'Actividad sospechosa detectada: {client_ip}',
                message=f"Tipo: {analysis.get('attack_type', 'unknown')} - Path: {path}",
                source_ip=client_ip
            )

    return None


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


@app.route('/security-dashboard')
@login_required
def security_dashboard():
    """Dashboard de seguridad avanzado"""
    return render_template('security_dashboard.html')


@app.route('/alerts')
@login_required
def alerts_page():
    """Página de gestión de alertas"""
    return render_template('alerts.html')


@app.route('/ip-analysis')
@login_required
def ip_analysis_page():
    """Página de análisis de IPs"""
    return render_template('ip_analysis.html')


@app.route('/ml-training')
@login_required
def ml_training_page():
    """Página de entrenamiento ML"""
    return render_template('ml_training.html')


@app.route('/ml-suggestions')
@login_required
def ml_suggestions_page():
    """Página de sugerencias ML"""
    return render_template('ml_suggestions.html')


@app.route('/log-import')
@login_required
def log_import_page():
    """Página de importación de logs históricos"""
    return render_template('log_import.html')


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
    db_stats = db_manager.get_dashboard_stats()

    stats = {
        'blocked_ips': db_stats.get('total_blocked_ips', 0),
        'active_threats': db_stats.get('active_threats', 0),
        'total_events_24h': db_stats.get('total_events_24h', 0),
        'critical_events_24h': db_stats.get('critical_events_24h', 0),
        'pending_alerts': db_stats.get('pending_alerts', 0),
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


# --- Gestión de Eventos de Seguridad ---
@app.route('/api/security/events', methods=['GET'])
@login_required
def get_security_events():
    """Obtener eventos de seguridad"""
    limit = request.args.get('limit', 100, type=int)
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')

    events = db_manager.get_security_events(limit=limit, severity=severity, event_type=event_type)
    return jsonify({'events': events})


@app.route('/api/security/events/<int:event_id>', methods=['GET'])
@login_required
def get_security_event(event_id):
    """Obtener detalles de un evento de seguridad"""
    event = db_manager.get_event_by_id(event_id)
    if event:
        return jsonify({'success': True, 'event': event})
    return jsonify({'success': False, 'error': 'Event not found'}), 404


# --- Gestión de IPs Bloqueadas ---
@app.route('/api/security/blocked-ips', methods=['GET'])
@login_required
def get_blocked_ips_api():
    """Obtener lista de IPs bloqueadas"""
    blocked_ips = db_manager.get_blocked_ips()
    return jsonify({'blocked_ips': blocked_ips})


@app.route('/api/security/block-ip', methods=['POST'])
@login_required
def block_ip_manual():
    """Bloquear IP manualmente"""
    data = request.json
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Manual block')
    duration_hours = data.get('duration_hours', 24)

    if not ip_address:
        return jsonify({'success': False, 'error': 'IP address required'}), 400

    result = db_manager.block_ip(
        ip_address=ip_address,
        reason=reason,
        blocked_by=current_user.username,
        duration_hours=duration_hours
    )

    return jsonify({'success': result})


@app.route('/api/security/unblock-ip', methods=['POST'])
@login_required
def unblock_ip_api():
    """Desbloquear IP"""
    data = request.json
    ip_address = data.get('ip_address')

    if not ip_address:
        return jsonify({'success': False, 'error': 'IP address required'}), 400

    result = db_manager.unblock_ip(ip_address)
    return jsonify({'success': result})


# --- Gestión de Alertas ---
@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    """Obtener alertas"""
    status = request.args.get('status', 'pending')
    severity = request.args.get('severity')
    limit = request.args.get('limit', 50, type=int)

    alerts = db_manager.get_alerts(status=status, severity=severity, limit=limit)
    return jsonify({'alerts': alerts})


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """Marcar alerta como resuelta"""
    data = request.json
    resolution_notes = data.get('resolution_notes', '')

    result = db_manager.resolve_alert(alert_id, current_user.username, resolution_notes)
    return jsonify({'success': result})


@app.route('/api/alerts/<int:alert_id>/dismiss', methods=['POST'])
@login_required
def dismiss_alert(alert_id):
    """Descartar alerta"""
    result = db_manager.dismiss_alert(alert_id)
    return jsonify({'success': result})


# --- Análisis de IP ---
@app.route('/api/security/analyze-ip/<ip_address>', methods=['GET'])
@login_required
def analyze_ip(ip_address):
    """Analizar IP completa (geo, reputación, historial)"""
    enriched_data = geo_intelligence.enrich_ip_data(ip_address)
    return jsonify(enriched_data)


# --- Estadísticas de Ataques ---
@app.route('/api/security/attack-stats', methods=['GET'])
@login_required
def get_attack_stats():
    """Obtener estadísticas de ataques"""
    hours = request.args.get('hours', 24, type=int)
    stats = db_manager.get_attack_statistics(hours=hours)
    return jsonify(stats)


# --- Whitelist / Blacklist ---
@app.route('/api/security/whitelist', methods=['GET'])
@login_required
def get_whitelist():
    """Obtener whitelist de IPs"""
    whitelist = db_manager.get_whitelist()
    return jsonify({'whitelist': whitelist})


@app.route('/api/security/whitelist', methods=['POST'])
@login_required
def add_to_whitelist():
    """Agregar IP a whitelist"""
    data = request.json
    ip_address = data.get('ip_address')
    reason = data.get('reason', '')

    if not ip_address:
        return jsonify({'success': False, 'error': 'IP address required'}), 400

    result = db_manager.add_to_whitelist(ip_address, reason, current_user.username)
    return jsonify({'success': result})


@app.route('/api/security/whitelist/<ip_address>', methods=['DELETE'])
@login_required
def remove_from_whitelist(ip_address):
    """Eliminar IP de whitelist"""
    result = db_manager.remove_from_whitelist(ip_address)
    return jsonify({'success': result})


@app.route('/api/security/blacklist', methods=['GET'])
@login_required
def get_blacklist():
    """Obtener blacklist de IPs"""
    blacklist = db_manager.get_blacklist()
    return jsonify({'blacklist': blacklist})


@app.route('/api/security/blacklist', methods=['POST'])
@login_required
def add_to_blacklist():
    """Agregar IP a blacklist"""
    data = request.json
    ip_address = data.get('ip_address')
    reason = data.get('reason', '')

    if not ip_address:
        return jsonify({'success': False, 'error': 'IP address required'}), 400

    result = db_manager.add_to_blacklist(ip_address, reason, current_user.username)
    return jsonify({'success': result})


# --- Importación de Logs Históricos ---
@app.route('/api/logs/available-files', methods=['GET'])
@login_required
def get_available_log_files():
    """Obtener archivos de logs disponibles en el sistema"""
    available = log_analyzer.get_available_log_files()
    return jsonify({'available_logs': available})


@app.route('/api/logs/import/nginx-access', methods=['POST'])
@login_required
def import_nginx_access_logs():
    """Importar logs de Nginx access.log"""
    data = request.json
    log_file_path = data.get('log_file_path')
    limit = data.get('limit')

    result = log_analyzer.import_nginx_access_logs(log_file_path, limit=limit)
    return jsonify(result)


@app.route('/api/logs/import/ssh-auth', methods=['POST'])
@login_required
def import_ssh_auth_logs():
    """Importar logs de SSH auth.log"""
    data = request.json
    log_file_path = data.get('log_file_path')
    limit = data.get('limit')

    result = log_analyzer.import_ssh_auth_logs(log_file_path, limit=limit)
    return jsonify(result)


@app.route('/api/logs/import/batch', methods=['POST'])
@login_required
def import_logs_batch():
    """Importar múltiples archivos de logs"""
    data = request.json
    nginx_access = data.get('nginx_access')
    nginx_error = data.get('nginx_error')
    ssh_auth = data.get('ssh_auth')
    limit_per_file = data.get('limit_per_file')

    result = log_analyzer.batch_import_logs(
        nginx_access=nginx_access,
        nginx_error=nginx_error,
        ssh_auth=ssh_auth,
        limit_per_file=limit_per_file
    )
    return jsonify(result)


# --- Machine Learning ---
@app.route('/api/ml/train', methods=['POST'])
@login_required
def train_ml_model():
    """Entrenar modelo de Machine Learning"""
    data = request.json
    days_back = data.get('days_back', 30)
    test_size = data.get('test_size', 0.2)
    random_state = data.get('random_state', 42)

    result = ml_detector.train_model(test_size=test_size, random_state=random_state)
    return jsonify(result)


@app.route('/api/ml/model-info', methods=['GET'])
@login_required
def get_ml_model_info():
    """Obtener información del modelo ML"""
    info = ml_detector.get_model_info()
    return jsonify(info)


@app.route('/api/ml/predict', methods=['POST'])
@login_required
def ml_predict():
    """Predecir si un evento es malicioso usando ML"""
    event_data = request.json
    prediction = ml_detector.predict(event_data)
    return jsonify(prediction)


@app.route('/api/ml/suggestions', methods=['GET'])
@login_required
def get_ml_suggestions():
    """Obtener sugerencias de IPs sospechosas según ML"""
    hours_back = request.args.get('hours_back', 24, type=int)
    min_confidence = request.args.get('min_confidence', 0.6, type=float)

    # Verificar si el modelo está entrenado
    if ml_detector.model is None:
        return jsonify({
            'model_trained': False,
            'suggestions': [],
            'message': 'Modelo no entrenado. Por favor entrena el modelo primero.'
        })

    suggestions = ml_detector.get_suspicious_ips(
        hours_back=hours_back,
        min_confidence=min_confidence
    )

    return jsonify({
        'model_trained': True,
        'suggestions': suggestions,
        'total': len(suggestions)
    })


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
