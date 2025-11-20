"""
Sistema de Backup y Restauración de Base de Datos
Permite exportar e importar la base de datos SQLite completa
"""

import os
import shutil
import sqlite3
import zipfile
from datetime import datetime
from pathlib import Path
import json


class DatabaseBackup:
    """Gestor de backup y restauración de base de datos"""

    def __init__(self, db_path='database/security.db'):
        """
        Inicializar gestor de backup

        Args:
            db_path: Ruta al archivo de base de datos SQLite
        """
        self.db_path = db_path
        self.backup_dir = 'backups'

        # Crear directorio de backups si no existe
        os.makedirs(self.backup_dir, exist_ok=True)

    def export_database(self, include_metadata=True):
        """
        Exportar base de datos completa a un archivo ZIP

        Args:
            include_metadata: Incluir metadata del backup (fecha, versión, etc.)

        Returns:
            dict: Información del backup creado
                {
                    'success': True,
                    'backup_file': 'path/to/backup.zip',
                    'size_bytes': 12345,
                    'timestamp': '2025-11-20T...',
                    'tables_count': 30,
                    'records_count': 5000
                }
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f'security_db_backup_{timestamp}.zip'
            backup_path = os.path.join(self.backup_dir, backup_filename)

            print(f"\n[BACKUP] Iniciando exportación de base de datos...")
            print(f"  Archivo origen: {self.db_path}")
            print(f"  Archivo destino: {backup_path}")

            # Verificar que la base de datos existe
            if not os.path.exists(self.db_path):
                return {
                    'success': False,
                    'error': f'Base de datos no encontrada: {self.db_path}'
                }

            # Obtener estadísticas de la base de datos
            stats = self._get_database_stats()

            # Crear archivo ZIP con la base de datos
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Agregar archivo de base de datos
                zipf.write(self.db_path, arcname='security.db')

                # Agregar metadata si se solicita
                if include_metadata:
                    metadata = {
                        'export_date': datetime.now().isoformat(),
                        'db_file': self.db_path,
                        'tables_count': stats.get('tables_count', 0),
                        'total_records': stats.get('total_records', 0),
                        'tables': stats.get('tables', []),
                        'version': '1.0.0',
                        'system': 'Security Monitor'
                    }

                    # Crear archivo temporal con metadata
                    metadata_json = json.dumps(metadata, indent=2)
                    zipf.writestr('metadata.json', metadata_json)

            # Obtener tamaño del backup
            backup_size = os.path.getsize(backup_path)

            print(f"  [OK] Backup creado exitosamente")
            print(f"  Tamaño: {backup_size / 1024:.2f} KB")
            print(f"  Tablas: {stats.get('tables_count', 0)}")
            print(f"  Registros: {stats.get('total_records', 0)}")

            return {
                'success': True,
                'backup_file': backup_path,
                'backup_filename': backup_filename,
                'size_bytes': backup_size,
                'size_kb': round(backup_size / 1024, 2),
                'size_mb': round(backup_size / (1024 * 1024), 2),
                'timestamp': datetime.now().isoformat(),
                'tables_count': stats.get('tables_count', 0),
                'total_records': stats.get('total_records', 0),
                'tables': stats.get('tables', [])
            }

        except Exception as e:
            print(f"  [ERROR] Error al exportar base de datos: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e)
            }

    def import_database(self, zip_file_path, backup_current=True):
        """
        Importar base de datos desde un archivo ZIP

        Args:
            zip_file_path: Ruta al archivo ZIP con el backup
            backup_current: Crear backup de la BD actual antes de importar

        Returns:
            dict: Resultado de la importación
                {
                    'success': True,
                    'message': 'Base de datos importada exitosamente',
                    'backup_file': 'path/to/current_backup.zip' (si backup_current=True),
                    'records_imported': 5000
                }
        """
        try:
            print(f"\n[IMPORT] Iniciando importación de base de datos...")
            print(f"  Archivo: {zip_file_path}")

            # Verificar que el archivo ZIP existe
            if not os.path.exists(zip_file_path):
                return {
                    'success': False,
                    'error': f'Archivo de backup no encontrado: {zip_file_path}'
                }

            # Crear backup de la base de datos actual antes de importar
            current_backup_info = None
            if backup_current and os.path.exists(self.db_path):
                print("  [INFO] Creando backup de la base de datos actual...")
                current_backup_info = self.export_database(include_metadata=True)
                if current_backup_info['success']:
                    print(f"  [OK] Backup actual guardado: {current_backup_info['backup_filename']}")
                else:
                    print(f"  [WARN] No se pudo crear backup actual: {current_backup_info.get('error')}")

            # Crear directorio temporal para extraer
            temp_dir = os.path.join(self.backup_dir, 'temp_import')
            os.makedirs(temp_dir, exist_ok=True)

            # Extraer archivo ZIP
            print("  [INFO] Extrayendo archivo ZIP...")
            with zipfile.ZipFile(zip_file_path, 'r') as zipf:
                zipf.extractall(temp_dir)

            # Buscar archivo de base de datos
            db_file = os.path.join(temp_dir, 'security.db')
            if not os.path.exists(db_file):
                # Limpiar directorio temporal
                shutil.rmtree(temp_dir)
                return {
                    'success': False,
                    'error': 'El archivo ZIP no contiene security.db'
                }

            # Leer metadata si existe
            metadata = {}
            metadata_file = os.path.join(temp_dir, 'metadata.json')
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                print(f"  [INFO] Metadata encontrada:")
                print(f"    Fecha de exportación: {metadata.get('export_date')}")
                print(f"    Tablas: {metadata.get('tables_count')}")
                print(f"    Registros: {metadata.get('total_records')}")

            # Crear backup del directorio database si existe
            db_dir = os.path.dirname(self.db_path)
            if not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)

            # Reemplazar base de datos actual
            print("  [INFO] Reemplazando base de datos...")
            if os.path.exists(self.db_path):
                os.remove(self.db_path)

            shutil.copy2(db_file, self.db_path)

            # Verificar que la importación fue exitosa
            stats = self._get_database_stats()

            # Limpiar directorio temporal
            shutil.rmtree(temp_dir)

            print(f"  [OK] Base de datos importada exitosamente")
            print(f"  Tablas: {stats.get('tables_count', 0)}")
            print(f"  Registros: {stats.get('total_records', 0)}")

            result = {
                'success': True,
                'message': 'Base de datos importada exitosamente',
                'tables_count': stats.get('tables_count', 0),
                'total_records': stats.get('total_records', 0),
                'tables': stats.get('tables', []),
                'metadata': metadata
            }

            if current_backup_info:
                result['backup_file'] = current_backup_info.get('backup_filename')
                result['backup_path'] = current_backup_info.get('backup_file')

            return result

        except Exception as e:
            print(f"  [ERROR] Error al importar base de datos: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e)
            }

    def list_backups(self):
        """
        Listar todos los backups disponibles

        Returns:
            list: Lista de backups con su información
        """
        try:
            backups = []

            if not os.path.exists(self.backup_dir):
                return backups

            for filename in os.listdir(self.backup_dir):
                if filename.endswith('.zip') and filename.startswith('security_db_backup_'):
                    filepath = os.path.join(self.backup_dir, filename)

                    # Obtener información del archivo
                    stat = os.stat(filepath)

                    # Intentar leer metadata del ZIP
                    metadata = {}
                    try:
                        with zipfile.ZipFile(filepath, 'r') as zipf:
                            if 'metadata.json' in zipf.namelist():
                                with zipf.open('metadata.json') as f:
                                    metadata = json.load(f)
                    except:
                        pass

                    backups.append({
                        'filename': filename,
                        'filepath': filepath,
                        'size_bytes': stat.st_size,
                        'size_kb': round(stat.st_size / 1024, 2),
                        'size_mb': round(stat.st_size / (1024 * 1024), 2),
                        'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        'modified_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'metadata': metadata
                    })

            # Ordenar por fecha de modificación (más reciente primero)
            backups.sort(key=lambda x: x['modified_at'], reverse=True)

            return backups

        except Exception as e:
            print(f"Error listando backups: {e}")
            return []

    def delete_backup(self, backup_filename):
        """
        Eliminar un backup específico

        Args:
            backup_filename: Nombre del archivo de backup a eliminar

        Returns:
            dict: Resultado de la operación
        """
        try:
            filepath = os.path.join(self.backup_dir, backup_filename)

            if not os.path.exists(filepath):
                return {
                    'success': False,
                    'error': f'Backup no encontrado: {backup_filename}'
                }

            os.remove(filepath)

            return {
                'success': True,
                'message': f'Backup eliminado: {backup_filename}'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _get_database_stats(self):
        """
        Obtener estadísticas de la base de datos

        Returns:
            dict: Estadísticas de la base de datos
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Obtener lista de tablas
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [row[0] for row in cursor.fetchall()]

            # Contar registros en cada tabla
            table_stats = []
            total_records = 0

            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    total_records += count

                    table_stats.append({
                        'name': table,
                        'records': count
                    })
                except:
                    table_stats.append({
                        'name': table,
                        'records': 0
                    })

            conn.close()

            return {
                'tables_count': len(tables),
                'total_records': total_records,
                'tables': table_stats
            }

        except Exception as e:
            print(f"Error obteniendo estadísticas: {e}")
            return {
                'tables_count': 0,
                'total_records': 0,
                'tables': []
            }
