"""
Rutas para Configuración de Bloqueo Geográfico
Permite configurar el filtrado de tráfico por país
"""

from flask import Blueprint, render_template, jsonify, request, session as flask_session, redirect, url_for
from database.db_manager import DatabaseManager
from modules.geo_service import GeoLocationService
import json

geo_config_bp = Blueprint('geo_config', __name__, url_prefix='/geo-config')

@geo_config_bp.route('/')
def index():
    """Página de configuración de bloqueo geográfico"""
    if 'user_id' not in flask_session:
        return redirect(url_for('auth.login'))

    return render_template('geo_config.html')


@geo_config_bp.route('/api/config', methods=['GET'])
def get_config():
    """Obtener configuración actual de bloqueo geográfico"""
    try:
        db = DatabaseManager()
        config = db.get_geo_config()

        # Parsear la lista de países desde JSON
        if config and 'countries' in config:
            try:
                config['countries'] = json.loads(config['countries']) if config['countries'] else []
            except:
                config['countries'] = []

        return jsonify({
            'success': True,
            'config': config
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@geo_config_bp.route('/api/config', methods=['POST'])
def update_config():
    """Actualizar configuración de bloqueo geográfico"""
    try:
        data = request.json
        db = DatabaseManager()

        # Obtener valores del request
        enabled = data.get('enabled', False)
        mode = data.get('mode', 'whitelist')
        countries = data.get('countries', [])
        block_unknown = data.get('block_unknown', False)
        updated_by = flask_session.get('username', 'admin')

        # Actualizar configuración
        success = db.update_geo_config(
            enabled=enabled,
            mode=mode,
            countries=countries,
            block_unknown=block_unknown,
            updated_by=updated_by
        )

        if success:
            # Log de la acción
            db.log_action(
                log_level='info',
                module='geo_config',
                action='update_config',
                user_id=flask_session.get('user_id'),
                details=f"Filtrado geográfico: {'activado' if enabled else 'desactivado'}, modo: {mode}, países: {len(countries)}",
                success=True
            )

            return jsonify({
                'success': True,
                'message': 'Configuración actualizada correctamente'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Error al actualizar configuración'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@geo_config_bp.route('/api/countries/add', methods=['POST'])
def add_country():
    """Agregar un país a la lista de filtrado"""
    try:
        data = request.json
        country_code = data.get('country_code')

        if not country_code:
            return jsonify({
                'success': False,
                'error': 'Código de país requerido'
            }), 400

        db = DatabaseManager()
        updated_by = flask_session.get('username', 'admin')

        success = db.add_country_to_filter(country_code, updated_by=updated_by)

        if success:
            return jsonify({
                'success': True,
                'message': f'País {country_code} agregado correctamente'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Error al agregar país'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@geo_config_bp.route('/api/countries/remove', methods=['POST'])
def remove_country():
    """Remover un país de la lista de filtrado"""
    try:
        data = request.json
        country_code = data.get('country_code')

        if not country_code:
            return jsonify({
                'success': False,
                'error': 'Código de país requerido'
            }), 400

        db = DatabaseManager()
        updated_by = flask_session.get('username', 'admin')

        success = db.remove_country_from_filter(country_code, updated_by=updated_by)

        if success:
            return jsonify({
                'success': True,
                'message': f'País {country_code} removido correctamente'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'País no encontrado'
            }), 404

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@geo_config_bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Obtener estadísticas de tráfico por país"""
    try:
        db = DatabaseManager()

        # Obtener últimos 1000 eventos con geolocalización
        from database.models import SecurityEvent
        session = db.get_session()

        try:
            events = session.query(SecurityEvent).filter(
                SecurityEvent.geo_location != None,
                SecurityEvent.geo_location != ''
            ).order_by(SecurityEvent.timestamp.desc()).limit(1000).all()

            # Contar eventos por país
            country_stats = {}

            for event in events:
                if event.geo_location:
                    try:
                        geo_data = json.loads(event.geo_location)
                        country = geo_data.get('country', 'Unknown')
                        country_code = geo_data.get('country_code', 'XX')

                        if country_code not in country_stats:
                            country_stats[country_code] = {
                                'country': country,
                                'country_code': country_code,
                                'total_events': 0,
                                'critical': 0,
                                'high': 0,
                                'medium': 0,
                                'low': 0
                            }

                        country_stats[country_code]['total_events'] += 1

                        severity = event.severity or 'low'
                        if severity in country_stats[country_code]:
                            country_stats[country_code][severity] += 1

                    except:
                        continue

            # Convertir a lista ordenada por total de eventos
            stats_list = list(country_stats.values())
            stats_list.sort(key=lambda x: x['total_events'], reverse=True)

            return jsonify({
                'success': True,
                'statistics': stats_list,
                'total_countries': len(stats_list)
            })

        finally:
            session.close()

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@geo_config_bp.route('/api/test-ip', methods=['POST'])
def test_ip():
    """Probar si una IP sería bloqueada con la configuración actual"""
    try:
        data = request.json
        ip_address = data.get('ip_address')

        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'Dirección IP requerida'
            }), 400

        db = DatabaseManager()
        geo_service = GeoLocationService(db, use_api_fallback=True)

        # Obtener información del país de la IP
        geo_info = geo_service.get_country_info(ip_address)

        # Verificar si está permitida
        allowed, reason = geo_service.is_country_allowed(ip_address)

        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'country_info': geo_info,
            'is_allowed': allowed,
            'reason': reason
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@geo_config_bp.route('/api/available-countries', methods=['GET'])
def get_available_countries():
    """Obtener lista de países disponibles desde los eventos"""
    try:
        db = DatabaseManager()
        from database.models import SecurityEvent
        session = db.get_session()

        try:
            # Obtener todos los países únicos de los eventos
            events = session.query(SecurityEvent.geo_location).filter(
                SecurityEvent.geo_location != None,
                SecurityEvent.geo_location != ''
            ).distinct().all()

            countries_set = set()
            countries_list = []

            for (geo_location,) in events:
                if geo_location:
                    try:
                        geo_data = json.loads(geo_location)
                        country_code = geo_data.get('country_code', 'XX')
                        country_name = geo_data.get('country', 'Unknown')

                        if country_code not in countries_set and country_code != 'XX':
                            countries_set.add(country_code)
                            countries_list.append({
                                'code': country_code,
                                'name': country_name
                            })
                    except:
                        continue

            # Ordenar por nombre
            countries_list.sort(key=lambda x: x['name'])

            return jsonify({
                'success': True,
                'countries': countries_list,
                'total': len(countries_list)
            })

        finally:
            session.close()

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
