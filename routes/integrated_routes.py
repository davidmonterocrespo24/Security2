"""
Rutas Flask para el Dashboard Integrado (ML + Zeek + Fail2ban)
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from datetime import datetime


def create_integrated_blueprint(integrated_analyzer):
    """
    Crear blueprint con rutas del dashboard integrado

    Args:
        integrated_analyzer: Instancia de IntegratedAnalyzer

    Returns:
        Blueprint de Flask
    """
    integrated_bp = Blueprint('integrated', __name__, url_prefix='/integrated')

    # ==================== PAGINA WEB ====================

    @integrated_bp.route('/')
    @login_required
    def integrated_dashboard():
        """Pagina principal del dashboard integrado"""
        return render_template('integrated_dashboard.html')

    # ==================== API ENDPOINTS ====================

    @integrated_bp.route('/api/summary', methods=['GET'])
    @login_required
    def get_summary():
        """
        Obtener resumen general del dashboard

        Query params:
            hours_back: Horas hacia atras (default: 24)

        Returns:
            JSON con metricas generales
        """
        hours_back = request.args.get('hours_back', 24, type=int)

        try:
            summary = integrated_analyzer.get_dashboard_summary(hours_back=hours_back)
            return jsonify({
                'success': True,
                'summary': summary
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @integrated_bp.route('/api/top-threats', methods=['GET'])
    @login_required
    def get_top_threats():
        """
        Obtener top IPs mas peligrosas

        Query params:
            hours_back: Horas hacia atras (default: 24)
            limit: Numero maximo de IPs (default: 10)

        Returns:
            JSON con top IPs y sus scores
        """
        hours_back = request.args.get('hours_back', 24, type=int)
        limit = request.args.get('limit', 10, type=int)

        try:
            threats = integrated_analyzer.get_top_threats(
                hours_back=hours_back,
                limit=limit
            )
            return jsonify({
                'success': True,
                'threats': threats,
                'total': len(threats)
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @integrated_bp.route('/api/threat-map', methods=['GET'])
    @login_required
    def get_threat_map():
        """
        Obtener mapa de amenazas por pais

        Query params:
            hours_back: Horas hacia atras (default: 24)

        Returns:
            JSON con datos por pais para visualizacion geografica
        """
        hours_back = request.args.get('hours_back', 24, type=int)

        try:
            threat_map = integrated_analyzer.get_threat_map(hours_back=hours_back)
            return jsonify({
                'success': True,
                'map': threat_map,
                'countries': len(threat_map)
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @integrated_bp.route('/api/timeline', methods=['GET'])
    @login_required
    def get_timeline():
        """
        Obtener timeline de ataques

        Query params:
            hours_back: Horas hacia atras (default: 24)
            interval_minutes: Intervalo de agrupacion (default: 60)

        Returns:
            JSON con timeline de eventos agrupados
        """
        hours_back = request.args.get('hours_back', 24, type=int)
        interval_minutes = request.args.get('interval_minutes', 60, type=int)

        try:
            timeline = integrated_analyzer.get_attack_timeline(
                hours_back=hours_back,
                interval_minutes=interval_minutes
            )
            return jsonify({
                'success': True,
                'timeline': timeline,
                'total_intervals': len(timeline)
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @integrated_bp.route('/api/correlation', methods=['GET'])
    @login_required
    def get_correlation():
        """
        Obtener estadisticas de correlacion entre sistemas

        Query params:
            hours_back: Horas hacia atras (default: 24)

        Returns:
            JSON con estadisticas de como se relacionan ML, Zeek y Fail2ban
        """
        hours_back = request.args.get('hours_back', 24, type=int)

        try:
            correlation = integrated_analyzer.get_correlation_stats(hours_back=hours_back)
            return jsonify({
                'success': True,
                'correlation': correlation
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @integrated_bp.route('/api/ip/<ip_address>', methods=['GET'])
    @login_required
    def get_ip_details(ip_address):
        """
        Obtener detalles completos de una IP especifica

        Args:
            ip_address: Direccion IP a consultar

        Returns:
            JSON con informacion completa de la IP
        """
        try:
            details = integrated_analyzer.get_ip_details(ip_address)

            if not details:
                return jsonify({
                    'success': False,
                    'error': 'IP no encontrada o sin datos'
                }), 404

            return jsonify({
                'success': True,
                'ip_details': details
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @integrated_bp.route('/api/export', methods=['GET'])
    @login_required
    def export_data():
        """
        Exportar datos del dashboard en formato CSV o JSON

        Query params:
            format: 'csv' o 'json' (default: json)
            hours_back: Horas hacia atras (default: 24)
            data_type: 'threats' o 'timeline' (default: threats)

        Returns:
            Archivo CSV o JSON con datos
        """
        export_format = request.args.get('format', 'json')
        hours_back = request.args.get('hours_back', 24, type=int)
        data_type = request.args.get('data_type', 'threats')

        try:
            if data_type == 'threats':
                data = integrated_analyzer.get_top_threats(
                    hours_back=hours_back,
                    limit=100
                )
            elif data_type == 'timeline':
                data = integrated_analyzer.get_attack_timeline(
                    hours_back=hours_back,
                    interval_minutes=60
                )
            else:
                return jsonify({
                    'success': False,
                    'error': 'Tipo de datos invalido'
                }), 400

            if export_format == 'csv':
                import csv
                from io import StringIO
                from flask import make_response

                si = StringIO()
                if data_type == 'threats' and data:
                    fieldnames = ['ip', 'score', 'ml_confidence', 'zeek_detections',
                                 'fail2ban_bans', 'total_events', 'country', 'last_seen']
                    writer = csv.DictWriter(si, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in data:
                        writer.writerow({k: row.get(k, '') for k in fieldnames})
                elif data_type == 'timeline' and data:
                    fieldnames = ['timestamp', 'ml_detections', 'zeek_detections',
                                 'fail2ban_bans', 'total']
                    writer = csv.DictWriter(si, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in data:
                        writer.writerow({k: row.get(k, '') for k in fieldnames})

                output = make_response(si.getvalue())
                output.headers["Content-Disposition"] = f"attachment; filename={data_type}_{hours_back}h.csv"
                output.headers["Content-type"] = "text/csv"
                return output
            else:
                # JSON format
                return jsonify({
                    'success': True,
                    'data': data,
                    'export_time': datetime.utcnow().isoformat(),
                    'hours_back': hours_back
                })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return integrated_bp
