"""
Rutas Flask para Sistema de Tareas Programadas
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user


def create_task_blueprint(task_scheduler):
    """
    Crear blueprint con todas las rutas de tareas programadas

    Args:
        task_scheduler: Instancia de TaskScheduler

    Returns:
        Blueprint de Flask
    """
    task_bp = Blueprint('tasks', __name__, url_prefix='/tasks')

    # ==================== PÁGINAS WEB ====================

    @task_bp.route('/')
    @login_required
    def tasks_index():
        """Página principal de tareas programadas"""
        return render_template('tasks_manager.html')

    # ==================== API ENDPOINTS ====================

    @task_bp.route('/api/tasks', methods=['GET'])
    @login_required
    def get_all_tasks():
        """Obtener todas las tareas programadas"""
        result = task_scheduler.get_all_tasks()
        return jsonify(result)

    @task_bp.route('/api/tasks/<int:task_id>', methods=['GET'])
    @login_required
    def get_task(task_id):
        """Obtener una tarea específica"""
        result = task_scheduler.get_task(task_id)
        return jsonify(result)

    @task_bp.route('/api/tasks', methods=['POST'])
    @login_required
    def create_task():
        """
        Crear una nueva tarea programada

        Body (JSON):
        {
            "task_name": str,
            "description": str,
            "task_type": str,  # 'zeek_import', 'ml_analysis', 'cleanup', 'custom'
            "module_name": str,  # 'modules.zeek_analyzer'
            "function_name": str,  # 'import_zeek_logs_to_db'
            "function_params": {},
            "schedule_type": str,  # 'interval', 'daily', 'hourly'
            "interval_minutes": int,  # Para schedule_type='interval'
            "hour": int,  # Para schedule_type='daily'
            "minute": int
        }
        """
        data = request.json

        # Agregar usuario actual
        data['created_by'] = current_user.username if current_user.is_authenticated else 'system'

        result = task_scheduler.create_task(data)
        return jsonify(result)

    @task_bp.route('/api/tasks/<int:task_id>', methods=['PUT'])
    @login_required
    def update_task(task_id):
        """Actualizar una tarea"""
        data = request.json
        data['updated_by'] = current_user.username if current_user.is_authenticated else 'system'

        result = task_scheduler.update_task(task_id, data)
        return jsonify(result)

    @task_bp.route('/api/tasks/<int:task_id>', methods=['DELETE'])
    @login_required
    def delete_task(task_id):
        """Eliminar una tarea"""
        result = task_scheduler.delete_task(task_id)
        return jsonify(result)

    @task_bp.route('/api/tasks/<int:task_id>/toggle', methods=['POST'])
    @login_required
    def toggle_task(task_id):
        """Activar/Desactivar una tarea"""
        data = request.json
        enabled = data.get('enabled', True)

        result = task_scheduler.toggle_task(task_id, enabled)
        return jsonify(result)

    @task_bp.route('/api/tasks/<int:task_id>/execute', methods=['POST'])
    @login_required
    def execute_task_now(task_id):
        """Ejecutar una tarea inmediatamente (manualmente)"""
        result = task_scheduler.execute_task_now(task_id)
        return jsonify(result)

    @task_bp.route('/api/tasks/<int:task_id>/logs', methods=['GET'])
    @login_required
    def get_task_logs(task_id):
        """Obtener historial de ejecuciones de una tarea"""
        limit = request.args.get('limit', 50, type=int)
        result = task_scheduler.get_task_logs(task_id, limit)
        return jsonify(result)

    @task_bp.route('/api/worker/status', methods=['GET'])
    @login_required
    def get_worker_status():
        """Obtener estado del worker de tareas"""
        status = task_scheduler.get_worker_status()
        return jsonify({'success': True, **status})

    @task_bp.route('/api/worker/start', methods=['POST'])
    @login_required
    def start_worker():
        """Iniciar el worker de tareas"""
        result = task_scheduler.start_worker()
        return jsonify(result)

    @task_bp.route('/api/worker/stop', methods=['POST'])
    @login_required
    def stop_worker():
        """Detener el worker de tareas"""
        result = task_scheduler.stop_worker()
        return jsonify(result)

    # ==================== TAREAS PREDEFINIDAS ====================

    @task_bp.route('/api/tasks/templates', methods=['GET'])
    @login_required
    def get_task_templates():
        """Obtener plantillas de tareas predefinidas"""
        templates = [
            {
                'name': 'Zeek Log Import',
                'task_type': 'zeek_import',
                'description': 'Importar logs de Zeek a la base de datos cada 5 minutos',
                'module_name': 'modules.zeek_analyzer',
                'function_name': 'import_zeek_logs',
                'function_params': {'limit': 1000},
                'schedule_type': 'interval',
                'interval_minutes': 5
            },
            {
                'name': 'ML Analysis',
                'task_type': 'ml_analysis',
                'description': 'Analizar IPs sospechosas con Machine Learning cada hora',
                'module_name': 'modules.ml_detector',
                'function_name': 'analyze_suspicious_ips',
                'function_params': {},
                'schedule_type': 'hourly',
                'minute': 0
            },
            {
                'name': 'Database Cleanup',
                'task_type': 'cleanup',
                'description': 'Limpiar logs antiguos (> 90 días) diariamente a las 3 AM',
                'module_name': 'database.db_manager',
                'function_name': 'cleanup_old_logs',
                'function_params': {'days': 90},
                'schedule_type': 'daily',
                'hour': 3,
                'minute': 0
            },
            {
                'name': 'Threat Intel Update',
                'task_type': 'threat_intel',
                'description': 'Actualizar feeds de Threat Intelligence cada 6 horas',
                'module_name': 'modules.threat_intel',
                'function_name': 'update_feeds',
                'function_params': {},
                'schedule_type': 'interval',
                'interval_minutes': 360
            }
        ]

        return jsonify({'success': True, 'templates': templates})

    return task_bp
