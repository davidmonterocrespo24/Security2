"""
Rutas Flask para la gestión de Zeek Network Security Monitor
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user


def create_zeek_blueprint(zeek_manager, zeek_analyzer, zeek_detections):
    """
    Crear blueprint con todas las rutas de Zeek

    Args:
        zeek_manager: Instancia de ZeekManager
        zeek_analyzer: Instancia de ZeekAnalyzer
        zeek_detections: Instancia de ZeekDetections

    Returns:
        Blueprint de Flask
    """
    zeek_bp = Blueprint('zeek', __name__, url_prefix='/zeek')

    # ==================== PÁGINAS WEB ====================

    @zeek_bp.route('/')
    @login_required
    def zeek_index():
        """Página principal de Zeek (dashboard)"""
        return render_template('zeek_dashboard.html')

    @zeek_bp.route('/install')
    @login_required
    def zeek_install_page():
        """Página de instalación de Zeek"""
        return render_template('zeek_install.html')

    @zeek_bp.route('/config')
    @login_required
    def zeek_config_page():
        """Página de configuración de Zeek"""
        return render_template('zeek_config.html')

    @zeek_bp.route('/logs')
    @login_required
    def zeek_logs_page():
        """Página de visualización de logs de Zeek"""
        return render_template('zeek_logs.html')

    @zeek_bp.route('/detections')
    @login_required
    def zeek_detections_page():
        """Página de detecciones avanzadas (port scans, DNS tunneling, etc)"""
        return render_template('zeek_detections.html')

    # ==================== API ENDPOINTS ====================

    # --- Estado e instalación ---

    @zeek_bp.route('/api/status', methods=['GET'])
    @login_required
    def get_zeek_status():
        """Obtener estado completo de Zeek"""
        install_status = zeek_manager.check_zeek_installed()
        service_status = zeek_manager.get_zeek_status()
        config = zeek_manager.get_config()

        return jsonify({
            'success': True,
            'installed': install_status['installed'],
            'version': install_status.get('version'),
            'running': service_status.get('running', False),
            'nodes': service_status.get('nodes', []),
            'config': config
        })

    @zeek_bp.route('/api/install', methods=['POST'])
    @login_required
    def install_zeek():
        """Instalar Zeek"""
        data = request.json
        method = data.get('method', 'package')

        result = zeek_manager.install_zeek(method=method)
        return jsonify(result)

    @zeek_bp.route('/api/version', methods=['GET'])
    @login_required
    def get_zeek_version():
        """Obtener versión de Zeek instalada"""
        version = zeek_manager.get_zeek_version()
        return jsonify({'version': version})

    # --- Control del servicio ---

    @zeek_bp.route('/api/start', methods=['POST'])
    @login_required
    def start_zeek():
        """Iniciar Zeek"""
        data = request.json
        interface = data.get('interface')

        result = zeek_manager.start_zeek(interface=interface)
        return jsonify(result)

    @zeek_bp.route('/api/stop', methods=['POST'])
    @login_required
    def stop_zeek():
        """Detener Zeek"""
        result = zeek_manager.stop_zeek()
        return jsonify(result)

    @zeek_bp.route('/api/restart', methods=['POST'])
    @login_required
    def restart_zeek():
        """Reiniciar Zeek"""
        result = zeek_manager.restart_zeek()
        return jsonify(result)

    # --- Configuración ---

    @zeek_bp.route('/api/config', methods=['GET'])
    @login_required
    def get_zeek_config():
        """Obtener configuración de Zeek"""
        config = zeek_manager.get_config()
        return jsonify({'success': True, 'config': config})

    @zeek_bp.route('/api/config', methods=['POST'])
    @login_required
    def update_zeek_config():
        """Actualizar configuración de Zeek"""
        data = request.json
        interface = data.get('interface')
        log_dir = data.get('log_dir')
        options = data.get('options', {})

        result = zeek_manager.configure_zeek(
            interface=interface,
            log_dir=log_dir,
            options=options
        )
        return jsonify(result)

    @zeek_bp.route('/api/interfaces', methods=['GET'])
    @login_required
    def get_network_interfaces():
        """Obtener interfaces de red disponibles"""
        interfaces = zeek_manager.get_interfaces()
        return jsonify({'interfaces': interfaces})

    # --- Logs ---

    @zeek_bp.route('/api/logs/files', methods=['GET'])
    @login_required
    def get_log_files():
        """Obtener archivos de log disponibles"""
        log_files = zeek_manager.get_log_files()
        return jsonify({'log_files': log_files})

    @zeek_bp.route('/api/logs/import', methods=['POST'])
    @login_required
    def import_logs():
        """Importar logs de Zeek a la base de datos"""
        data = request.json
        log_type = data.get('log_type', 'all')
        limit = data.get('limit')

        result = zeek_analyzer.import_zeek_logs_to_db(log_type=log_type, limit=limit)
        return jsonify(result)

    @zeek_bp.route('/api/logs/connections', methods=['GET'])
    @login_required
    def get_connections():
        """Obtener conexiones desde conn.log (desde BD)"""
        from database.models import ZeekConnection
        from database.db_manager import DatabaseManager

        db = DatabaseManager()
        session = db.get_session()

        try:
            limit = request.args.get('limit', 100, type=int)
            source_ip = request.args.get('source_ip')
            dest_ip = request.args.get('dest_ip')
            service = request.args.get('service')

            query = session.query(ZeekConnection).order_by(ZeekConnection.timestamp.desc())

            if source_ip:
                query = query.filter(ZeekConnection.source_ip == source_ip)
            if dest_ip:
                query = query.filter(ZeekConnection.dest_ip == dest_ip)
            if service:
                query = query.filter(ZeekConnection.service == service)

            conns = query.limit(limit).all()
            return jsonify({
                'success': True,
                'connections': [c.to_dict() for c in conns],
                'total': len(conns)
            })
        finally:
            session.close()

    @zeek_bp.route('/api/logs/dns', methods=['GET'])
    @login_required
    def get_dns_queries():
        """Obtener queries DNS desde dns.log (desde BD)"""
        from database.models import ZeekDNS
        from database.db_manager import DatabaseManager

        db = DatabaseManager()
        session = db.get_session()

        try:
            limit = request.args.get('limit', 100, type=int)
            source_ip = request.args.get('source_ip')
            query_filter = request.args.get('query')

            query_obj = session.query(ZeekDNS).order_by(ZeekDNS.timestamp.desc())

            if source_ip:
                query_obj = query_obj.filter(ZeekDNS.source_ip == source_ip)
            if query_filter:
                query_obj = query_obj.filter(ZeekDNS.query.like(f'%{query_filter}%'))

            dns_queries = query_obj.limit(limit).all()
            return jsonify({
                'success': True,
                'dns_queries': [q.to_dict() for q in dns_queries],
                'total': len(dns_queries)
            })
        finally:
            session.close()

    @zeek_bp.route('/api/logs/ssl', methods=['GET'])
    @login_required
    def get_ssl_connections():
        """Obtener conexiones SSL desde ssl.log (desde BD)"""
        from database.models import ZeekSSL
        from database.db_manager import DatabaseManager

        db = DatabaseManager()
        session = db.get_session()

        try:
            limit = request.args.get('limit', 100, type=int)
            source_ip = request.args.get('source_ip')
            server_name = request.args.get('server_name')

            query = session.query(ZeekSSL).order_by(ZeekSSL.timestamp.desc())

            if source_ip:
                query = query.filter(ZeekSSL.source_ip == source_ip)
            if server_name:
                query = query.filter(ZeekSSL.server_name.like(f'%{server_name}%'))

            ssl_conns = query.limit(limit).all()
            return jsonify({
                'success': True,
                'ssl_connections': [s.to_dict() for s in ssl_conns],
                'total': len(ssl_conns)
            })
        finally:
            session.close()

    @zeek_bp.route('/api/logs/http', methods=['GET'])
    @login_required
    def get_http_requests():
        """Obtener requests HTTP desde http.log (desde BD)"""
        from database.models import ZeekHTTP
        from database.db_manager import DatabaseManager

        db = DatabaseManager()
        session = db.get_session()

        try:
            limit = request.args.get('limit', 100, type=int)
            source_ip = request.args.get('source_ip')
            host = request.args.get('host')

            query = session.query(ZeekHTTP).order_by(ZeekHTTP.timestamp.desc())

            if source_ip:
                query = query.filter(ZeekHTTP.source_ip == source_ip)
            if host:
                query = query.filter(ZeekHTTP.host.like(f'%{host}%'))

            http_reqs = query.limit(limit).all()
            return jsonify({
                'success': True,
                'http_requests': [h.to_dict() for h in http_reqs],
                'total': len(http_reqs)
            })
        finally:
            session.close()

    @zeek_bp.route('/api/logs/notices', methods=['GET'])
    @login_required
    def get_zeek_notices():
        """Obtener alertas/notices de Zeek desde notice.log (desde BD)"""
        from database.models import ZeekNotice
        from database.db_manager import DatabaseManager

        db = DatabaseManager()
        session = db.get_session()

        try:
            limit = request.args.get('limit', 100, type=int)
            severity = request.args.get('severity')
            resolved = request.args.get('resolved', 'false')

            query = session.query(ZeekNotice).order_by(ZeekNotice.timestamp.desc())

            if severity:
                query = query.filter(ZeekNotice.severity == severity)

            if resolved == 'false':
                query = query.filter(ZeekNotice.is_resolved == False)

            notices = query.limit(limit).all()
            return jsonify({
                'success': True,
                'notices': [n.to_dict() for n in notices],
                'total': len(notices)
            })
        finally:
            session.close()

    # --- Detecciones Avanzadas ---

    @zeek_bp.route('/api/detections/port-scans', methods=['GET'])
    @login_required
    def detect_port_scans():
        """Detectar escaneos de puertos"""
        hours_back = request.args.get('hours_back', 1, type=int)
        min_ports = request.args.get('min_ports', 15, type=int)

        scanners = zeek_detections.detect_port_scan_from_conn_log(
            hours_back=hours_back,
            min_ports=min_ports
        )

        return jsonify({
            'success': True,
            'port_scanners': scanners,
            'total': len(scanners)
        })

    @zeek_bp.route('/api/detections/dns-analysis', methods=['GET'])
    @login_required
    def analyze_dns():
        """Analizar queries DNS sospechosas"""
        hours_back = request.args.get('hours_back', 24, type=int)

        analysis = zeek_detections.analyze_dns_queries(hours_back=hours_back)

        return jsonify({
            'success': True,
            'analysis': analysis
        })

    @zeek_bp.route('/api/detections/ssl-analysis', methods=['GET'])
    @login_required
    def analyze_ssl():
        """Analizar conexiones SSL/TLS"""
        hours_back = request.args.get('hours_back', 24, type=int)

        analysis = zeek_detections.analyze_ssl_connections(hours_back=hours_back)

        return jsonify({
            'success': True,
            'analysis': analysis
        })

    @zeek_bp.route('/api/detections/beaconing', methods=['GET'])
    @login_required
    def detect_beaconing():
        """Detectar beaconing (C&C)"""
        hours_back = request.args.get('hours_back', 24, type=int)
        threshold = request.args.get('threshold', 0.9, type=float)

        suspects = zeek_detections.detect_beaconing(
            hours_back=hours_back,
            regularity_threshold=threshold
        )

        return jsonify({
            'success': True,
            'beaconing_suspects': suspects,
            'total': len(suspects)
        })

    # --- Estadísticas ---

    @zeek_bp.route('/api/stats', methods=['GET'])
    @login_required
    def get_zeek_stats():
        """Obtener estadísticas generales de Zeek"""
        from database.models import ZeekConnection, ZeekDNS, ZeekSSL, ZeekHTTP, ZeekNotice
        from database.db_manager import DatabaseManager

        db = DatabaseManager()
        session = db.get_session()

        try:
            hours_back = request.args.get('hours_back', 24, type=int)
            from datetime import datetime, timedelta
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            stats = {
                'total_connections': session.query(ZeekConnection).filter(
                    ZeekConnection.timestamp >= cutoff
                ).count(),
                'total_dns_queries': session.query(ZeekDNS).filter(
                    ZeekDNS.timestamp >= cutoff
                ).count(),
                'total_ssl_connections': session.query(ZeekSSL).filter(
                    ZeekSSL.timestamp >= cutoff
                ).count(),
                'total_http_requests': session.query(ZeekHTTP).filter(
                    ZeekHTTP.timestamp >= cutoff
                ).count(),
                'total_notices': session.query(ZeekNotice).filter(
                    ZeekNotice.timestamp >= cutoff
                ).count(),
                'unresolved_notices': session.query(ZeekNotice).filter(
                    ZeekNotice.timestamp >= cutoff,
                    ZeekNotice.is_resolved == False
                ).count()
            }

            return jsonify({
                'success': True,
                'stats': stats,
                'hours_back': hours_back
            })
        finally:
            session.close()

    # --- Top Connections / IPs ---

    @zeek_bp.route('/api/stats/top-connections', methods=['GET'])
    @login_required
    def get_top_connections():
        """Obtener top conexiones"""
        hours_back = request.args.get('hours_back', 24, type=int)
        limit = request.args.get('limit', 10, type=int)

        top_conns = zeek_analyzer.get_top_connections(hours_back=hours_back, limit=limit)

        return jsonify({
            'success': True,
            'top_connections': top_conns
        })

    # --- Scripts personalizados ---

    @zeek_bp.route('/api/scripts/deploy', methods=['POST'])
    @login_required
    def deploy_scripts():
        """Desplegar scripts personalizados de Zeek"""
        data = request.json
        scripts = data.get('scripts', {})

        result = zeek_manager.deploy_zeek_scripts(scripts)
        return jsonify(result)

    return zeek_bp
