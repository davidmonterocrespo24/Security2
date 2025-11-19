"""
API Routes - Auto-Block Policies
Endpoints para gestión de políticas de auto-bloqueo basadas en ML
"""

from flask import Blueprint, jsonify, request
from datetime import datetime
import traceback


def create_auto_block_blueprint(db_manager, auto_blocker):
    """
    Crear Blueprint para rutas de auto-bloqueo

    Args:
        db_manager: Instancia de DatabaseManager
        auto_blocker: Instancia de AutoBlocker
    """
    auto_block_bp = Blueprint('auto_block', __name__, url_prefix='/auto-block')


    # ============================================================================
    # POLÍTICAS - CRUD
    # ============================================================================

    @auto_block_bp.route('/api/policies', methods=['GET'])
    def get_policies():
        """
        GET /auto-block/api/policies
        Obtener todas las políticas de auto-bloqueo

        Query params:
            - enabled: true/false (filtrar por estado)

        Response:
            {
                "success": true,
                "policies": [
                    {
                        "id": 1,
                        "policy_name": "default",
                        "description": "...",
                        "enabled": false,
                        "criteria": {...},
                        "block_config": {...},
                        "statistics": {...},
                        "created_at": "2025-11-19T...",
                        "updated_at": null
                    }
                ],
                "total": 2
            }
        """
        try:
            # Filtro por estado
            enabled_filter = request.args.get('enabled')

            policies = db_manager.get_auto_block_policies()

            # Aplicar filtro si existe
            if enabled_filter is not None:
                enabled_bool = enabled_filter.lower() == 'true'
                policies = [p for p in policies if p.enabled == enabled_bool]

            # Formatear respuesta
            policies_data = []
            for policy in policies:
                policies_data.append({
                    'id': policy.id,
                    'policy_name': policy.policy_name,
                    'description': policy.description,
                    'enabled': policy.enabled,
                    'criteria': {
                        'min_ml_confidence': policy.min_ml_confidence,
                        'min_threat_score': policy.min_threat_score,
                        'min_severity': policy.min_severity,
                        'min_events': policy.min_events,
                        'require_multiple_sources': policy.require_multiple_sources
                    },
                    'block_config': {
                        'default_block_duration': policy.default_block_duration,
                        'permanent_block': policy.permanent_block,
                        'apply_to_fail2ban': policy.apply_to_fail2ban,
                        'whitelist_enabled': policy.whitelist_enabled,
                        'exclude_internal_ips': policy.exclude_internal_ips
                    },
                    'statistics': {
                        'total_blocks': policy.total_blocks,
                        'last_block_at': policy.last_block_at.isoformat() if policy.last_block_at else None
                    },
                    'created_at': policy.created_at.isoformat() if policy.created_at else None,
                    'created_by': policy.created_by,
                    'updated_at': policy.updated_at.isoformat() if policy.updated_at else None,
                    'updated_by': policy.updated_by
                })

            return jsonify({
                'success': True,
                'policies': policies_data,
                'total': len(policies_data)
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    @auto_block_bp.route('/api/policies/<int:policy_id>', methods=['GET'])
    def get_policy(policy_id):
        """
        GET /auto-block/api/policies/<id>
        Obtener detalles de una política específica

        Response:
            {
                "success": true,
                "policy": {...}
            }
        """
        try:
            policies = db_manager.get_auto_block_policies()
            policy = next((p for p in policies if p.id == policy_id), None)

            if not policy:
                return jsonify({
                    'success': False,
                    'error': f'Política {policy_id} no encontrada'
                }), 404

            return jsonify({
                'success': True,
                'policy': {
                    'id': policy.id,
                    'policy_name': policy.policy_name,
                    'description': policy.description,
                    'enabled': policy.enabled,
                    'criteria': {
                        'min_ml_confidence': policy.min_ml_confidence,
                        'min_threat_score': policy.min_threat_score,
                        'min_severity': policy.min_severity,
                        'min_events': policy.min_events,
                        'require_multiple_sources': policy.require_multiple_sources
                    },
                    'block_config': {
                        'default_block_duration': policy.default_block_duration,
                        'permanent_block': policy.permanent_block,
                        'apply_to_fail2ban': policy.apply_to_fail2ban,
                        'whitelist_enabled': policy.whitelist_enabled,
                        'exclude_internal_ips': policy.exclude_internal_ips
                    },
                    'statistics': {
                        'total_blocks': policy.total_blocks,
                        'last_block_at': policy.last_block_at.isoformat() if policy.last_block_at else None
                    },
                    'created_at': policy.created_at.isoformat() if policy.created_at else None,
                    'created_by': policy.created_by,
                    'updated_at': policy.updated_at.isoformat() if policy.updated_at else None,
                    'updated_by': policy.updated_by
                }
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    @auto_block_bp.route('/api/policies', methods=['POST'])
    def create_policy():
        """
        POST /auto-block/api/policies
        Crear nueva política de auto-bloqueo

        Body:
            {
                "policy_name": "custom",
                "description": "Mi política personalizada",
                "enabled": false,
                "min_ml_confidence": 85.0,
                "min_threat_score": 70.0,
                "min_severity": "high",
                "min_events": 3,
                "require_multiple_sources": true,
                "default_block_duration": 24,
                "permanent_block": false,
                "apply_to_fail2ban": true,
                "whitelist_enabled": true,
                "exclude_internal_ips": true,
                "created_by": "admin"
            }

        Response:
            {
                "success": true,
                "policy_id": 3,
                "message": "Política creada exitosamente"
            }
        """
        try:
            data = request.get_json()

            # Validar campos requeridos
            if not data.get('policy_name'):
                return jsonify({
                    'success': False,
                    'error': 'policy_name es requerido'
                }), 400

            # Validar severidad
            valid_severities = ['low', 'medium', 'high', 'critical']
            if data.get('min_severity') and data['min_severity'] not in valid_severities:
                return jsonify({
                    'success': False,
                    'error': f'min_severity debe ser uno de: {", ".join(valid_severities)}'
                }), 400

            # Crear política
            policy_dict = db_manager.create_auto_block_policy(
                policy_name=data['policy_name'],
                description=data.get('description', ''),
                enabled=data.get('enabled', False),
                min_ml_confidence=data.get('min_ml_confidence', 85.0),
                min_threat_score=data.get('min_threat_score', 70.0),
                min_severity=data.get('min_severity', 'high'),
                min_events=data.get('min_events', 3),
                require_multiple_sources=data.get('require_multiple_sources', True),
                default_block_duration=data.get('default_block_duration', 24),
                permanent_block=data.get('permanent_block', False),
                apply_to_fail2ban=data.get('apply_to_fail2ban', True),
                whitelist_enabled=data.get('whitelist_enabled', True),
                exclude_internal_ips=data.get('exclude_internal_ips', True),
                created_by=data.get('created_by', 'api')
            )

            if not policy_dict:
                return jsonify({
                    'success': False,
                    'error': 'Error creating policy'
                }), 500

            return jsonify({
                'success': True,
                'policy_id': policy_dict['id'],
                'message': 'Política creada exitosamente'
            }), 201

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    @auto_block_bp.route('/api/policies/<int:policy_id>', methods=['PUT'])
    def update_policy(policy_id):
        """
        PUT /auto-block/api/policies/<id>
        Actualizar política existente

        Body: (todos los campos son opcionales)
            {
                "description": "Nueva descripción",
                "min_ml_confidence": 90.0,
                "updated_by": "admin"
            }

        Response:
            {
                "success": true,
                "message": "Política actualizada exitosamente"
            }
        """
        try:
            data = request.get_json()

            # Verificar que la política existe
            policies = db_manager.get_auto_block_policies()
            policy = next((p for p in policies if p.id == policy_id), None)

            if not policy:
                return jsonify({
                    'success': False,
                    'error': f'Política {policy_id} no encontrada'
                }), 404

            # Validar severidad si se proporciona
            if 'min_severity' in data:
                valid_severities = ['low', 'medium', 'high', 'critical']
                if data['min_severity'] not in valid_severities:
                    return jsonify({
                        'success': False,
                        'error': f'min_severity debe ser uno de: {", ".join(valid_severities)}'
                    }), 400

            # Actualizar política
            db_manager.update_auto_block_policy(policy_id, **data)

            return jsonify({
                'success': True,
                'message': 'Política actualizada exitosamente'
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    @auto_block_bp.route('/api/policies/<int:policy_id>', methods=['DELETE'])
    def delete_policy(policy_id):
        """
        DELETE /auto-block/api/policies/<id>
        Eliminar política

        Response:
            {
                "success": true,
                "message": "Política eliminada exitosamente"
            }
        """
        try:
            # Verificar que la política existe
            policies = db_manager.get_auto_block_policies()
            policy = next((p for p in policies if p.id == policy_id), None)

            if not policy:
                return jsonify({
                    'success': False,
                    'error': f'Política {policy_id} no encontrada'
                }), 404

            # No permitir eliminar política activa
            if policy.enabled:
                return jsonify({
                    'success': False,
                    'error': 'No se puede eliminar una política activa. Desactívala primero.'
                }), 400

            # Eliminar política
            db_manager.delete_auto_block_policy(policy_id)

            return jsonify({
                'success': True,
                'message': 'Política eliminada exitosamente'
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    # ============================================================================
    # ACTIVACIÓN/DESACTIVACIÓN
    # ============================================================================

    @auto_block_bp.route('/api/policies/<int:policy_id>/toggle', methods=['POST'])
    def toggle_policy(policy_id):
        """
        POST /auto-block/api/policies/<id>/toggle
        Activar o desactivar política

        Body:
            {
                "enabled": true,
                "updated_by": "admin"
            }

        Response:
            {
                "success": true,
                "enabled": true,
                "message": "Política activada exitosamente"
            }
        """
        try:
            data = request.get_json()
            enabled = data.get('enabled', True)

            # Verificar que la política existe
            policies = db_manager.get_auto_block_policies()
            policy = next((p for p in policies if p.id == policy_id), None)

            if not policy:
                return jsonify({
                    'success': False,
                    'error': f'Política {policy_id} no encontrada'
                }), 404

            # Si se está activando, desactivar otras políticas primero
            # (solo una política puede estar activa a la vez)
            if enabled:
                for p in policies:
                    if p.enabled and p.id != policy_id:
                        db_manager.enable_auto_block_policy(p.id, False)

            # Activar/desactivar política
            db_manager.enable_auto_block_policy(policy_id, enabled)

            # Si se proporciona updated_by, actualizar
            if 'updated_by' in data:
                db_manager.update_auto_block_policy(
                    policy_id,
                    updated_by=data['updated_by']
                )

            return jsonify({
                'success': True,
                'enabled': enabled,
                'message': f'Política {"activada" if enabled else "desactivada"} exitosamente'
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    @auto_block_bp.route('/api/policies/active', methods=['GET'])
    def get_active_policy():
        """
        GET /auto-block/api/policies/active
        Obtener política activa actual

        Response:
            {
                "success": true,
                "policy": {...} or null
            }
        """
        try:
            policy = db_manager.get_active_auto_block_policy()

            if not policy:
                return jsonify({
                    'success': True,
                    'policy': None,
                    'message': 'No hay ninguna política activa'
                })

            return jsonify({
                'success': True,
                'policy': {
                    'id': policy.id,
                    'policy_name': policy.policy_name,
                    'description': policy.description,
                    'enabled': policy.enabled,
                    'criteria': {
                        'min_ml_confidence': policy.min_ml_confidence,
                        'min_threat_score': policy.min_threat_score,
                        'min_severity': policy.min_severity,
                        'min_events': policy.min_events,
                        'require_multiple_sources': policy.require_multiple_sources
                    },
                    'block_config': {
                        'default_block_duration': policy.default_block_duration,
                        'permanent_block': policy.permanent_block,
                        'apply_to_fail2ban': policy.apply_to_fail2ban,
                        'whitelist_enabled': policy.whitelist_enabled,
                        'exclude_internal_ips': policy.exclude_internal_ips
                    },
                    'statistics': {
                        'total_blocks': policy.total_blocks,
                        'last_block_at': policy.last_block_at.isoformat() if policy.last_block_at else None
                    }
                }
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    # ============================================================================
    # ESTADÍSTICAS Y MONITOREO
    # ============================================================================

    @auto_block_bp.route('/api/stats', methods=['GET'])
    def get_stats():
        """
        GET /auto-block/api/stats
        Obtener estadísticas de auto-bloqueo

        Query params:
            - hours: Horas hacia atrás (default: 24)

        Response:
            {
                "success": true,
                "stats": {
                    "total_evaluated": 150,
                    "total_blocked": 12,
                    "block_rate": 8.0,
                    "by_severity": {...},
                    "top_blocked_ips": [...],
                    "active_policy": {...}
                }
            }
        """
        try:
            hours = int(request.args.get('hours', 24))

            stats = auto_blocker.get_auto_block_stats(hours_back=hours)

            # Agregar política activa
            active_policy = db_manager.get_active_auto_block_policy()
            if active_policy:
                stats['active_policy'] = {
                    'id': active_policy.id,
                    'name': active_policy.policy_name,
                    'total_blocks': active_policy.total_blocks
                }
            else:
                stats['active_policy'] = None

            return jsonify({
                'success': True,
                'stats': stats,
                'hours_back': hours
            })

        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    # ============================================================================
    # PROCESAMIENTO Y DRY-RUN
    # ============================================================================

    @auto_block_bp.route('/api/process', methods=['POST'])
    def process_predictions():
        """
        POST /auto-block/api/process
        Procesar predicciones ML para auto-bloqueo

        Body:
            {
                "dry_run": true,
                "hours_back": 24,
                "limit": 100
            }

        Response:
            {
                "success": true,
                "results": {
                    "evaluated": 50,
                    "blocked": 5,
                    "already_blocked": 3,
                    "whitelisted": 2,
                    "below_threshold": 40
                },
                "blocked_ips": ["1.2.3.4", ...],
                "dry_run": true
            }
        """
        try:
            data = request.get_json() or {}

            dry_run = data.get('dry_run', True)  # Por defecto, dry-run
            hours_back = data.get('hours_back', 24)
            limit = data.get('limit', 100)

            # Verificar que hay una política activa
            active_policy = db_manager.get_active_auto_block_policy()
            if not active_policy and not dry_run:
                return jsonify({
                    'success': False,
                    'error': 'No hay ninguna política activa. Active una política primero.'
                }), 400

            # Obtener predicciones ML recientes
            from datetime import datetime, timedelta
            cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)

            session = db_manager.get_session()
            from database.models import MLPrediction

            predictions = session.query(MLPrediction)\
                .filter(MLPrediction.last_seen >= cutoff_time)\
                .order_by(MLPrediction.ml_confidence.desc())\
                .limit(limit)\
                .all()

            session.close()

            # Convertir a diccionarios
            predictions_data = []
            for pred in predictions:
                predictions_data.append({
                    'ip_address': pred.ip_address,
                    'ml_confidence': pred.ml_confidence,
                    'threat_score': pred.threat_score,
                    'severity': pred.severity,
                    'event_count': pred.event_count,
                    'first_seen': pred.first_seen,
                    'last_seen': pred.last_seen
                })

            # Procesar con auto-blocker
            results = auto_blocker.process_ml_predictions(predictions_data, dry_run=dry_run)

            return jsonify({
                'success': True,
                'results': results,
                'predictions_analyzed': len(predictions_data),
                'hours_back': hours_back,
                'dry_run': dry_run,
                'policy_used': active_policy.policy_name if active_policy else 'none'
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


    # ============================================================================
    # DASHBOARD WEB
    # ============================================================================

    @auto_block_bp.route('/', methods=['GET'])
    @auto_block_bp.route('/dashboard', methods=['GET'])
    def dashboard():
        """
        GET /auto-block/dashboard
        Dashboard de configuración de auto-bloqueo
        """
        from flask import render_template
        return render_template('auto_block_dashboard.html')


    return auto_block_bp
