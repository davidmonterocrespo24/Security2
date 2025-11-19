"""
Rutas Flask para la gestión del Sistema de Alertas
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import json


def create_alert_blueprint(db_manager, alert_manager):
    """
    Crear blueprint con todas las rutas de Alertas

    Args:
        db_manager: Instancia de DatabaseManager
        alert_manager: Instancia de AlertManager

    Returns:
        Blueprint de Flask
    """
    alert_bp = Blueprint('alerts', __name__, url_prefix='/alerts')

    # ==================== PÁGINAS WEB ====================

    @alert_bp.route('/')
    @login_required
    def alerts_index():
        """Página principal de configuración de alertas"""
        return render_template('alerts_config.html')

    @alert_bp.route('/logs')
    @login_required
    def alerts_logs():
        """Página de historial de alertas enviadas"""
        return render_template('alerts_logs.html')

    # ==================== API ENDPOINTS ====================

    # --- CANALES DE NOTIFICACIÓN ---

    @alert_bp.route('/api/channels', methods=['GET'])
    @login_required
    def get_channels():
        """Obtener todos los canales de notificación"""
        from database.models import AlertChannel

        session = db_manager.get_session()
        try:
            channels = session.query(AlertChannel).all()
            return jsonify({
                'success': True,
                'channels': [c.to_dict() for c in channels],
                'total': len(channels)
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/channels/<int:channel_id>', methods=['GET'])
    @login_required
    def get_channel(channel_id):
        """Obtener un canal específico"""
        from database.models import AlertChannel

        session = db_manager.get_session()
        try:
            channel = session.query(AlertChannel).filter_by(id=channel_id).first()
            if not channel:
                return jsonify({'success': False, 'error': 'Canal no encontrado'}), 404

            return jsonify({
                'success': True,
                'channel': channel.to_dict()
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/channels', methods=['POST'])
    @login_required
    def create_channel():
        """Crear un nuevo canal de notificación"""
        from database.models import AlertChannel

        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No se proporcionaron datos'}), 400

        required_fields = ['channel_name', 'channel_type', 'config']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Campo requerido: {field}'}), 400

        session = db_manager.get_session()
        try:
            # Verificar que el nombre no exista
            existing = session.query(AlertChannel).filter_by(channel_name=data['channel_name']).first()
            if existing:
                return jsonify({'success': False, 'error': 'Ya existe un canal con ese nombre'}), 400

            # Crear canal
            channel = AlertChannel(
                channel_name=data['channel_name'],
                channel_type=data['channel_type'],
                config=json.dumps(data['config']),
                is_enabled=data.get('is_enabled', True),
                created_by=current_user.username if current_user else 'unknown',
                description=data.get('description', '')
            )

            session.add(channel)
            session.commit()

            return jsonify({
                'success': True,
                'message': 'Canal creado exitosamente',
                'channel': channel.to_dict()
            })
        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/channels/<int:channel_id>', methods=['PUT'])
    @login_required
    def update_channel(channel_id):
        """Actualizar un canal de notificación"""
        from database.models import AlertChannel

        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No se proporcionaron datos'}), 400

        session = db_manager.get_session()
        try:
            channel = session.query(AlertChannel).filter_by(id=channel_id).first()
            if not channel:
                return jsonify({'success': False, 'error': 'Canal no encontrado'}), 404

            # Actualizar campos
            if 'channel_name' in data:
                # Verificar que el nombre no exista en otro canal
                existing = session.query(AlertChannel).filter(
                    AlertChannel.channel_name == data['channel_name'],
                    AlertChannel.id != channel_id
                ).first()
                if existing:
                    return jsonify({'success': False, 'error': 'Ya existe un canal con ese nombre'}), 400
                channel.channel_name = data['channel_name']

            if 'config' in data:
                channel.config = json.dumps(data['config'])
            if 'is_enabled' in data:
                channel.is_enabled = data['is_enabled']
            if 'description' in data:
                channel.description = data['description']

            channel.updated_at = datetime.utcnow()

            session.commit()

            return jsonify({
                'success': True,
                'message': 'Canal actualizado exitosamente',
                'channel': channel.to_dict()
            })
        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/channels/<int:channel_id>', methods=['DELETE'])
    @login_required
    def delete_channel(channel_id):
        """Eliminar un canal de notificación"""
        from database.models import AlertChannel

        session = db_manager.get_session()
        try:
            channel = session.query(AlertChannel).filter_by(id=channel_id).first()
            if not channel:
                return jsonify({'success': False, 'error': 'Canal no encontrado'}), 404

            session.delete(channel)
            session.commit()

            return jsonify({
                'success': True,
                'message': 'Canal eliminado exitosamente'
            })
        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/channels/<int:channel_id>/test', methods=['POST'])
    @login_required
    def test_channel(channel_id):
        """Enviar un mensaje de prueba al canal"""
        from database.models import AlertChannel

        session = db_manager.get_session()
        try:
            channel = session.query(AlertChannel).filter_by(id=channel_id).first()
            if not channel:
                return jsonify({'success': False, 'error': 'Canal no encontrado'}), 404

            if not channel.is_enabled:
                return jsonify({'success': False, 'error': 'El canal está deshabilitado'}), 400

            # Enviar email de prueba
            if channel.channel_type == 'email':
                config = json.loads(channel.config)
                recipients = config.get('recipients', [])
                if not recipients:
                    return jsonify({'success': False, 'error': 'No hay destinatarios configurados'}), 400

                result = alert_manager.send_email(
                    recipients=recipients,
                    subject='[TEST] Alerta de Prueba - Sistema de Seguridad VPS',
                    body='Este es un mensaje de prueba del sistema de alertas.\n\nSi recibes este email, el canal está configurado correctamente.',
                    html_body=None
                )

                if result['success']:
                    channel.is_verified = True
                    channel.successful_sends += 1
                    channel.total_alerts_sent += 1
                    channel.last_sent_at = datetime.utcnow()
                else:
                    channel.failed_sends += 1
                    channel.last_error = result.get('error', 'Error desconocido')

                session.commit()

                return jsonify(result)
            else:
                return jsonify({'success': False, 'error': f'Tipo de canal no soportado: {channel.channel_type}'}), 400

        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/channels/<int:channel_id>/toggle', methods=['POST'])
    @login_required
    def toggle_channel(channel_id):
        """Habilitar/deshabilitar un canal"""
        from database.models import AlertChannel

        session = db_manager.get_session()
        try:
            channel = session.query(AlertChannel).filter_by(id=channel_id).first()
            if not channel:
                return jsonify({'success': False, 'error': 'Canal no encontrado'}), 404

            channel.is_enabled = not channel.is_enabled
            channel.updated_at = datetime.utcnow()

            session.commit()

            return jsonify({
                'success': True,
                'message': f'Canal {"habilitado" if channel.is_enabled else "deshabilitado"}',
                'is_enabled': channel.is_enabled
            })
        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    # --- REGLAS DE ALERTA ---

    @alert_bp.route('/api/rules', methods=['GET'])
    @login_required
    def get_rules():
        """Obtener todas las reglas de alerta"""
        from database.models import AlertRule

        session = db_manager.get_session()
        try:
            rule_type = request.args.get('rule_type')
            is_enabled = request.args.get('is_enabled')

            query = session.query(AlertRule)

            if rule_type:
                query = query.filter(AlertRule.rule_type == rule_type)
            if is_enabled is not None:
                query = query.filter(AlertRule.is_enabled == (is_enabled.lower() == 'true'))

            rules = query.all()
            return jsonify({
                'success': True,
                'rules': [r.to_dict() for r in rules],
                'total': len(rules)
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/rules/<int:rule_id>', methods=['GET'])
    @login_required
    def get_rule(rule_id):
        """Obtener una regla específica"""
        from database.models import AlertRule

        session = db_manager.get_session()
        try:
            rule = session.query(AlertRule).filter_by(id=rule_id).first()
            if not rule:
                return jsonify({'success': False, 'error': 'Regla no encontrada'}), 404

            return jsonify({
                'success': True,
                'rule': rule.to_dict()
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/rules', methods=['POST'])
    @login_required
    def create_rule():
        """Crear una nueva regla de alerta"""
        from database.models import AlertRule

        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No se proporcionaron datos'}), 400

        required_fields = ['rule_name', 'rule_type', 'conditions']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Campo requerido: {field}'}), 400

        session = db_manager.get_session()
        try:
            # Verificar que el nombre no exista
            existing = session.query(AlertRule).filter_by(rule_name=data['rule_name']).first()
            if existing:
                return jsonify({'success': False, 'error': 'Ya existe una regla con ese nombre'}), 400

            # Crear regla
            rule = AlertRule(
                rule_name=data['rule_name'],
                rule_type=data['rule_type'],
                conditions=json.dumps(data['conditions']),
                severity_threshold=data.get('severity_threshold', 'LOW'),
                channel_ids=json.dumps(data.get('channel_ids', [])),
                cooldown_minutes=data.get('cooldown_minutes', 0),
                message_template=data.get('message_template', ''),
                is_enabled=data.get('is_enabled', True),
                created_by=current_user.username if current_user else 'unknown',
                description=data.get('description', '')
            )

            session.add(rule)
            session.commit()

            return jsonify({
                'success': True,
                'message': 'Regla creada exitosamente',
                'rule': rule.to_dict()
            })
        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/rules/<int:rule_id>', methods=['PUT'])
    @login_required
    def update_rule(rule_id):
        """Actualizar una regla de alerta"""
        from database.models import AlertRule

        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No se proporcionaron datos'}), 400

        session = db_manager.get_session()
        try:
            rule = session.query(AlertRule).filter_by(id=rule_id).first()
            if not rule:
                return jsonify({'success': False, 'error': 'Regla no encontrada'}), 404

            # Actualizar campos
            if 'rule_name' in data:
                existing = session.query(AlertRule).filter(
                    AlertRule.rule_name == data['rule_name'],
                    AlertRule.id != rule_id
                ).first()
                if existing:
                    return jsonify({'success': False, 'error': 'Ya existe una regla con ese nombre'}), 400
                rule.rule_name = data['rule_name']

            if 'conditions' in data:
                rule.conditions = json.dumps(data['conditions'])
            if 'severity_threshold' in data:
                rule.severity_threshold = data['severity_threshold']
            if 'channel_ids' in data:
                rule.channel_ids = json.dumps(data['channel_ids'])
            if 'cooldown_minutes' in data:
                rule.cooldown_minutes = data['cooldown_minutes']
            if 'message_template' in data:
                rule.message_template = data['message_template']
            if 'is_enabled' in data:
                rule.is_enabled = data['is_enabled']
            if 'description' in data:
                rule.description = data['description']

            rule.updated_at = datetime.utcnow()

            session.commit()

            return jsonify({
                'success': True,
                'message': 'Regla actualizada exitosamente',
                'rule': rule.to_dict()
            })
        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/rules/<int:rule_id>', methods=['DELETE'])
    @login_required
    def delete_rule(rule_id):
        """Eliminar una regla de alerta"""
        from database.models import AlertRule

        session = db_manager.get_session()
        try:
            rule = session.query(AlertRule).filter_by(id=rule_id).first()
            if not rule:
                return jsonify({'success': False, 'error': 'Regla no encontrada'}), 404

            session.delete(rule)
            session.commit()

            return jsonify({
                'success': True,
                'message': 'Regla eliminada exitosamente'
            })
        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/rules/<int:rule_id>/toggle', methods=['POST'])
    @login_required
    def toggle_rule(rule_id):
        """Habilitar/deshabilitar una regla"""
        from database.models import AlertRule

        session = db_manager.get_session()
        try:
            rule = session.query(AlertRule).filter_by(id=rule_id).first()
            if not rule:
                return jsonify({'success': False, 'error': 'Regla no encontrada'}), 404

            rule.is_enabled = not rule.is_enabled
            rule.updated_at = datetime.utcnow()

            session.commit()

            return jsonify({
                'success': True,
                'message': f'Regla {"habilitada" if rule.is_enabled else "deshabilitada"}',
                'is_enabled': rule.is_enabled
            })
        except Exception as e:
            session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    # --- LOGS DE ALERTAS ---

    @alert_bp.route('/api/logs', methods=['GET'])
    @login_required
    def get_alert_logs():
        """Obtener historial de alertas enviadas"""
        from database.models import AlertLog

        session = db_manager.get_session()
        try:
            limit = request.args.get('limit', 100, type=int)
            severity = request.args.get('severity')
            success_only = request.args.get('success', 'false').lower() == 'true'
            hours_back = request.args.get('hours_back', 24, type=int)

            cutoff = datetime.utcnow() - timedelta(hours=hours_back)
            query = session.query(AlertLog).filter(AlertLog.sent_at >= cutoff)

            if severity:
                query = query.filter(AlertLog.severity == severity.upper())
            if success_only:
                query = query.filter(AlertLog.success == True)

            logs = query.order_by(AlertLog.sent_at.desc()).limit(limit).all()

            return jsonify({
                'success': True,
                'logs': [log.to_dict() for log in logs],
                'total': len(logs)
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    @alert_bp.route('/api/logs/stats', methods=['GET'])
    @login_required
    def get_alert_stats():
        """Obtener estadísticas de alertas"""
        from database.models import AlertLog, AlertChannel, AlertRule

        session = db_manager.get_session()
        try:
            hours_back = request.args.get('hours_back', 24, type=int)
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            # Estadísticas generales
            total_sent = session.query(AlertLog).filter(AlertLog.sent_at >= cutoff).count()
            successful = session.query(AlertLog).filter(
                AlertLog.sent_at >= cutoff,
                AlertLog.success == True
            ).count()
            failed = total_sent - successful

            # Por severidad
            by_severity = {}
            for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                count = session.query(AlertLog).filter(
                    AlertLog.sent_at >= cutoff,
                    AlertLog.severity == severity
                ).count()
                by_severity[severity.lower()] = count

            # Canales y reglas activos
            active_channels = session.query(AlertChannel).filter(AlertChannel.is_enabled == True).count()
            active_rules = session.query(AlertRule).filter(AlertRule.is_enabled == True).count()

            # Top 5 reglas que más alertas han disparado
            top_rules = session.query(AlertLog.rule_id).filter(
                AlertLog.sent_at >= cutoff
            ).all()

            from collections import Counter
            rule_counts = Counter([r[0] for r in top_rules if r[0]])
            top_5_rules = []
            for rule_id, count in rule_counts.most_common(5):
                rule = session.query(AlertRule).filter_by(id=rule_id).first()
                if rule:
                    top_5_rules.append({
                        'rule_name': rule.rule_name,
                        'count': count
                    })

            return jsonify({
                'success': True,
                'stats': {
                    'total_sent': total_sent,
                    'successful': successful,
                    'failed': failed,
                    'success_rate': round((successful / total_sent * 100) if total_sent > 0 else 0, 2),
                    'by_severity': by_severity,
                    'active_channels': active_channels,
                    'active_rules': active_rules,
                    'top_rules': top_5_rules
                },
                'hours_back': hours_back
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            session.close()

    # --- PRUEBA MANUAL DE ALERTAS ---

    @alert_bp.route('/api/test-alert', methods=['POST'])
    @login_required
    def test_alert():
        """Disparar una alerta de prueba manualmente"""
        data = request.json or {}

        test_event = {
            'type': 'manual_test',
            'severity': data.get('severity', 'MEDIUM'),
            'ip': '127.0.0.1',
            'reason': data.get('message', 'Alerta de prueba manual desde el panel de control'),
            'timestamp': datetime.utcnow().isoformat(),
            'user': current_user.username if current_user else 'unknown'
        }

        try:
            result = alert_manager.process_alert(test_event)
            return jsonify({
                'success': True,
                'message': 'Alerta de prueba enviada',
                'result': result
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return alert_bp
