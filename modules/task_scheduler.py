"""
Sistema de Tareas Programadas (Scheduler)
Gestión de cron jobs desde el panel web
"""

import threading
import time
import importlib
import json
import traceback
from datetime import datetime, timedelta
from database.models import ScheduledTask, TaskLog


class TaskScheduler:
    """Gestor de tareas programadas"""

    def __init__(self, db_manager):
        self.db = db_manager
        self.running = False
        self.worker_thread = None

    def create_task(self, task_data):
        """
        Crear una nueva tarea programada

        Args:
            task_data: dict con los datos de la tarea
                {
                    'task_name': str,
                    'description': str,
                    'task_type': str,
                    'module_name': str,
                    'function_name': str,
                    'function_params': dict,
                    'schedule_type': str,  # 'interval', 'daily', 'hourly'
                    'interval_minutes': int,
                    'hour': int,
                    'minute': int
                }

        Returns:
            dict: {'success': bool, 'task_id': int, 'message': str}
        """
        try:
            session = self.db.get_session()

            # Verificar que no existe una tarea con el mismo nombre
            existing = session.query(ScheduledTask).filter_by(
                task_name=task_data['task_name']
            ).first()

            if existing:
                session.close()
                return {
                    'success': False,
                    'message': f"Ya existe una tarea con el nombre '{task_data['task_name']}'"
                }

            # Calcular next_run
            next_run = self._calculate_next_run(task_data)

            # Crear la tarea
            task = ScheduledTask(
                task_name=task_data['task_name'],
                description=task_data.get('description', ''),
                task_type=task_data['task_type'],
                module_name=task_data['module_name'],
                function_name=task_data['function_name'],
                function_params=json.dumps(task_data.get('function_params', {})),
                schedule_type=task_data['schedule_type'],
                interval_minutes=task_data.get('interval_minutes'),
                cron_expression=task_data.get('cron_expression'),
                hour=task_data.get('hour'),
                minute=task_data.get('minute', 0),
                is_enabled=task_data.get('is_enabled', True),
                timeout_seconds=task_data.get('timeout_seconds', 300),
                retry_on_failure=task_data.get('retry_on_failure', False),
                max_retries=task_data.get('max_retries', 3),
                alert_on_failure=task_data.get('alert_on_failure', True),
                next_run=next_run,
                created_by=task_data.get('created_by', 'system')
            )

            session.add(task)
            session.commit()

            task_id = task.id
            session.close()

            return {
                'success': True,
                'task_id': task_id,
                'message': f"Tarea '{task_data['task_name']}' creada exitosamente",
                'next_run': next_run.isoformat() if next_run else None
            }

        except Exception as e:
            return {
                'success': False,
                'message': f"Error creando tarea: {str(e)}"
            }

    def _calculate_next_run(self, task_data):
        """Calcular la próxima ejecución de una tarea"""
        now = datetime.utcnow()
        schedule_type = task_data['schedule_type']

        if schedule_type == 'interval':
            # Ejecutar cada X minutos
            minutes = task_data.get('interval_minutes', 5)
            return now + timedelta(minutes=minutes)

        elif schedule_type == 'hourly':
            # Ejecutar cada hora en el minuto especificado
            minute = task_data.get('minute', 0)
            next_run = now.replace(minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(hours=1)
            return next_run

        elif schedule_type == 'daily':
            # Ejecutar diariamente a una hora específica
            hour = task_data.get('hour', 0)
            minute = task_data.get('minute', 0)
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run

        else:
            # Por defecto, ejecutar en 5 minutos
            return now + timedelta(minutes=5)

    def get_all_tasks(self):
        """
        Obtener todas las tareas programadas

        Returns:
            list: Lista de tareas
        """
        try:
            session = self.db.get_session()
            tasks = session.query(ScheduledTask).all()
            tasks_list = [task.to_dict() for task in tasks]
            session.close()
            return {'success': True, 'tasks': tasks_list}
        except Exception as e:
            return {'success': False, 'message': str(e), 'tasks': []}

    def get_task(self, task_id):
        """Obtener una tarea específica"""
        try:
            session = self.db.get_session()
            task = session.query(ScheduledTask).filter_by(id=task_id).first()

            if not task:
                session.close()
                return {'success': False, 'message': 'Tarea no encontrada'}

            task_dict = task.to_dict()
            session.close()
            return {'success': True, 'task': task_dict}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def update_task(self, task_id, updates):
        """
        Actualizar una tarea programada

        Args:
            task_id: ID de la tarea
            updates: dict con campos a actualizar

        Returns:
            dict: {'success': bool, 'message': str}
        """
        try:
            session = self.db.get_session()
            task = session.query(ScheduledTask).filter_by(id=task_id).first()

            if not task:
                session.close()
                return {'success': False, 'message': 'Tarea no encontrada'}

            # Actualizar campos
            for key, value in updates.items():
                if hasattr(task, key):
                    if key == 'function_params' and isinstance(value, dict):
                        value = json.dumps(value)
                    setattr(task, key, value)

            task.updated_at = datetime.utcnow()

            # Recalcular next_run si se cambia el schedule
            if any(k in updates for k in ['schedule_type', 'interval_minutes', 'hour', 'minute']):
                task.next_run = self._calculate_next_run(task.to_dict())

            session.commit()
            session.close()

            return {'success': True, 'message': 'Tarea actualizada'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def delete_task(self, task_id):
        """Eliminar una tarea"""
        try:
            session = self.db.get_session()
            task = session.query(ScheduledTask).filter_by(id=task_id).first()

            if not task:
                session.close()
                return {'success': False, 'message': 'Tarea no encontrada'}

            session.delete(task)
            session.commit()
            session.close()

            return {'success': True, 'message': 'Tarea eliminada'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def toggle_task(self, task_id, enabled):
        """Activar/Desactivar una tarea"""
        return self.update_task(task_id, {'is_enabled': enabled})

    def execute_task_now(self, task_id):
        """
        Ejecutar una tarea inmediatamente (manualmente)

        Returns:
            dict: {'success': bool, 'message': str, 'result': dict}
        """
        try:
            session = self.db.get_session()
            task = session.query(ScheduledTask).filter_by(id=task_id).first()

            if not task:
                session.close()
                return {'success': False, 'message': 'Tarea no encontrada'}

            task_dict = task.to_dict()
            session.close()

            # Ejecutar la tarea
            result = self._execute_task(task_dict)

            return {
                'success': True,
                'message': 'Tarea ejecutada manualmente',
                'result': result
            }

        except Exception as e:
            return {
                'success': False,
                'message': f"Error ejecutando tarea: {str(e)}"
            }

    def _execute_task(self, task_dict):
        """
        Ejecutar una tarea específica

        Args:
            task_dict: Diccionario con los datos de la tarea

        Returns:
            dict: Resultado de la ejecución
        """
        task_id = task_dict['id']
        start_time = datetime.utcnow()

        try:
            # Marcar como corriendo
            session = self.db.get_session()
            task = session.query(ScheduledTask).filter_by(id=task_id).first()
            task.is_running = True
            task.last_run = start_time
            task.last_run_status = 'running'
            session.commit()
            session.close()

            # Importar módulo y función
            module = importlib.import_module(task_dict['module_name'])
            function = getattr(module, task_dict['function_name'])

            # Parsear parámetros
            params = {}
            if task_dict.get('function_params'):
                params = json.loads(task_dict['function_params'])

            # Ejecutar función
            result = function(**params)

            # Calcular duración
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()

            # Actualizar estado
            session = self.db.get_session()
            task = session.query(ScheduledTask).filter_by(id=task_id).first()
            task.is_running = False
            task.last_run_status = 'success'
            task.last_run_message = result.get('message', 'Completado exitosamente')
            task.last_run_duration = duration
            task.total_runs += 1
            task.successful_runs += 1
            task.next_run = self._calculate_next_run(task.to_dict())
            session.commit()
            session.close()

            # Registrar en TaskLog
            self._log_task_execution(
                task_id, start_time, end_time, duration,
                'success', result.get('message', 'OK'),
                None, result
            )

            return {
                'success': True,
                'duration': duration,
                'result': result
            }

        except Exception as e:
            # Error en ejecución
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            error_msg = str(e)
            error_details = traceback.format_exc()

            # Actualizar estado
            session = self.db.get_session()
            task = session.query(ScheduledTask).filter_by(id=task_id).first()
            task.is_running = False
            task.last_run_status = 'error'
            task.last_run_message = error_msg
            task.last_run_duration = duration
            task.total_runs += 1
            task.failed_runs += 1
            task.next_run = self._calculate_next_run(task.to_dict())
            session.commit()
            session.close()

            # Registrar error en TaskLog
            self._log_task_execution(
                task_id, start_time, end_time, duration,
                'error', error_msg, error_details, None
            )

            return {
                'success': False,
                'error': error_msg,
                'traceback': error_details
            }

    def _log_task_execution(self, task_id, start_time, end_time, duration,
                           status, message, error_details, output):
        """Registrar ejecución en TaskLog"""
        try:
            session = self.db.get_session()

            log = TaskLog(
                task_id=task_id,
                started_at=start_time,
                finished_at=end_time,
                duration=duration,
                status=status,
                message=message,
                error_details=error_details,
                output=json.dumps(output) if output else None,
                records_processed=output.get('records_processed', 0) if output else 0,
                records_created=output.get('records_created', 0) if output else 0
            )

            session.add(log)
            session.commit()
            session.close()
        except Exception as e:
            print(f"Error logging task execution: {e}")

    def get_task_logs(self, task_id, limit=50):
        """Obtener historial de ejecuciones de una tarea"""
        try:
            session = self.db.get_session()
            logs = session.query(TaskLog).filter_by(task_id=task_id)\
                .order_by(TaskLog.started_at.desc()).limit(limit).all()

            logs_list = [log.to_dict() for log in logs]
            session.close()

            return {'success': True, 'logs': logs_list}
        except Exception as e:
            return {'success': False, 'message': str(e), 'logs': []}

    # ==================== WORKER THREAD ====================

    def start_worker(self):
        """Iniciar el worker de tareas programadas en background"""
        if self.running:
            return {'success': False, 'message': 'Worker ya está corriendo'}

        self.running = True
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()

        return {'success': True, 'message': 'Worker de tareas iniciado'}

    def stop_worker(self):
        """Detener el worker de tareas programadas"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)

        return {'success': True, 'message': 'Worker de tareas detenido'}

    def _worker_loop(self):
        """Loop principal del worker - se ejecuta en background"""
        print("[TaskScheduler] Worker iniciado")

        while self.running:
            try:
                now = datetime.utcnow()

                # Obtener tareas que deben ejecutarse
                session = self.db.get_session()
                tasks = session.query(ScheduledTask).filter(
                    ScheduledTask.is_enabled == True,
                    ScheduledTask.is_running == False,
                    ScheduledTask.next_run <= now
                ).all()

                tasks_to_run = [task.to_dict() for task in tasks]
                session.close()

                # Ejecutar cada tarea
                for task_dict in tasks_to_run:
                    print(f"[TaskScheduler] Ejecutando tarea: {task_dict['task_name']}")
                    self._execute_task(task_dict)

                # Dormir 60 segundos antes de la próxima verificación
                time.sleep(60)

            except Exception as e:
                print(f"[TaskScheduler] Error en worker loop: {e}")
                time.sleep(60)

        print("[TaskScheduler] Worker detenido")

    def get_worker_status(self):
        """Obtener estado del worker"""
        return {
            'running': self.running,
            'thread_alive': self.worker_thread.is_alive() if self.worker_thread else False
        }
