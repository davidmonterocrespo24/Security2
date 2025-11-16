"""
Paquete de Base de Datos
"""

from database.models import init_database, get_session, insert_default_config
from database.db_manager import DatabaseManager

# Inicializar base de datos al importar
try:
    init_database()
    insert_default_config()
except Exception as e:
    print(f"Warning: Could not initialize database: {e}")

__all__ = ['DatabaseManager', 'get_session', 'init_database']
