"""
API Routes para gestión de backup y restauración de base de datos
"""

from flask import Blueprint, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
import os
import traceback


def create_database_blueprint(db_backup_manager):
    """
    Crear blueprint para gestión de base de datos

    Args:
        db_backup_manager: Instancia de DatabaseBackup

    Returns:
        Blueprint: Blueprint configurado
    """
    db_bp = Blueprint('database', __name__, url_prefix='/database')

    # ========================================================================
    # PÁGINA PRINCIPAL
    # ========================================================================

    @db_bp.route('/config', methods=['GET'])
    def config_page():
        """
        GET /database/config
        Página de configuración de base de datos
        """
        return render_template('database_config.html')

    # ========================================================================
    # EXPORTAR BASE DE DATOS
    # ========================================================================

    @db_bp.route('/api/export', methods=['POST'])
    def export_database():
        """
        POST /database/api/export
        Exportar base de datos completa a un archivo ZIP

        Request Body (JSON):
            {
                "include_metadata": true
            }

        Response:
            {
                "success": true,
                "backup_file": "security_db_backup_20251120_035600.zip",
                "size_kb": 1234.56,
                "tables_count": 30,
                "total_records": 5000,
                "download_url": "/database/api/download/security_db_backup_20251120_035600.zip"
            }
        """
        try:
            data = request.get_json() or {}
            include_metadata = data.get('include_metadata', True)

            print("\n[API] Solicitud de exportación de base de datos")
            print(f"  Include metadata: {include_metadata}")

            # Exportar base de datos
            result = db_backup_manager.export_database(include_metadata=include_metadata)

            if result['success']:
                # Agregar URL de descarga
                result['download_url'] = f"/database/api/download/{result['backup_filename']}"

            return jsonify(result)

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # DESCARGAR BACKUP
    # ========================================================================

    @db_bp.route('/api/download/<filename>', methods=['GET'])
    def download_backup(filename):
        """
        GET /database/api/download/<filename>
        Descargar un archivo de backup

        Response:
            Archivo ZIP para descarga
        """
        try:
            # Validar nombre de archivo (seguridad)
            filename = secure_filename(filename)

            if not filename.startswith('security_db_backup_') or not filename.endswith('.zip'):
                return jsonify({
                    'success': False,
                    'error': 'Nombre de archivo inválido'
                }), 400

            filepath = os.path.join(db_backup_manager.backup_dir, filename)

            if not os.path.exists(filepath):
                return jsonify({
                    'success': False,
                    'error': 'Archivo no encontrado'
                }), 404

            return send_file(
                filepath,
                as_attachment=True,
                download_name=filename,
                mimetype='application/zip'
            )

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # IMPORTAR BASE DE DATOS
    # ========================================================================

    @db_bp.route('/api/import', methods=['POST'])
    def import_database():
        """
        POST /database/api/import
        Importar base de datos desde un archivo ZIP

        Request:
            Multipart form data con archivo 'backup_file'
            Query params:
                - backup_current: true/false (crear backup antes de importar)

        Response:
            {
                "success": true,
                "message": "Base de datos importada exitosamente",
                "tables_count": 30,
                "total_records": 5000,
                "backup_file": "security_db_backup_20251120_040000.zip" (si backup_current=true)
            }
        """
        try:
            # Verificar que se envió un archivo
            if 'backup_file' not in request.files:
                return jsonify({
                    'success': False,
                    'error': 'No se proporcionó archivo de backup'
                }), 400

            file = request.files['backup_file']

            if file.filename == '':
                return jsonify({
                    'success': False,
                    'error': 'Archivo vacío'
                }), 400

            # Validar extensión
            if not file.filename.endswith('.zip'):
                return jsonify({
                    'success': False,
                    'error': 'El archivo debe ser un ZIP'
                }), 400

            # Parámetro para hacer backup antes de importar
            backup_current = request.args.get('backup_current', 'true').lower() == 'true'

            # Guardar archivo temporalmente
            temp_dir = os.path.join(db_backup_manager.backup_dir, 'temp_uploads')
            os.makedirs(temp_dir, exist_ok=True)

            filename = secure_filename(file.filename)
            temp_filepath = os.path.join(temp_dir, filename)
            file.save(temp_filepath)

            print(f"\n[API] Solicitud de importación de base de datos")
            print(f"  Archivo: {filename}")
            print(f"  Backup actual: {backup_current}")

            # Importar base de datos
            result = db_backup_manager.import_database(temp_filepath, backup_current=backup_current)

            # Limpiar archivo temporal
            try:
                os.remove(temp_filepath)
            except:
                pass

            return jsonify(result)

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # LISTAR BACKUPS
    # ========================================================================

    @db_bp.route('/api/backups', methods=['GET'])
    def list_backups():
        """
        GET /database/api/backups
        Listar todos los backups disponibles

        Response:
            {
                "success": true,
                "backups": [
                    {
                        "filename": "security_db_backup_20251120_035600.zip",
                        "size_kb": 1234.56,
                        "created_at": "2025-11-20T03:56:00",
                        "tables_count": 30,
                        "total_records": 5000
                    }
                ]
            }
        """
        try:
            backups = db_backup_manager.list_backups()

            # Agregar URL de descarga a cada backup
            for backup in backups:
                backup['download_url'] = f"/database/api/download/{backup['filename']}"

            return jsonify({
                'success': True,
                'backups': backups,
                'count': len(backups)
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # ELIMINAR BACKUP
    # ========================================================================

    @db_bp.route('/api/backups/<filename>', methods=['DELETE'])
    def delete_backup(filename):
        """
        DELETE /database/api/backups/<filename>
        Eliminar un backup específico

        Response:
            {
                "success": true,
                "message": "Backup eliminado: ..."
            }
        """
        try:
            # Validar nombre de archivo
            filename = secure_filename(filename)

            if not filename.startswith('security_db_backup_') or not filename.endswith('.zip'):
                return jsonify({
                    'success': False,
                    'error': 'Nombre de archivo inválido'
                }), 400

            result = db_backup_manager.delete_backup(filename)

            return jsonify(result)

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # ESTADÍSTICAS DE BASE DE DATOS
    # ========================================================================

    @db_bp.route('/api/stats', methods=['GET'])
    def get_database_stats():
        """
        GET /database/api/stats
        Obtener estadísticas de la base de datos actual

        Response:
            {
                "success": true,
                "stats": {
                    "tables_count": 30,
                    "total_records": 5000,
                    "tables": [
                        {"name": "security_events", "records": 1000},
                        ...
                    ]
                }
            }
        """
        try:
            stats = db_backup_manager._get_database_stats()

            return jsonify({
                'success': True,
                'stats': stats
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    return db_bp
