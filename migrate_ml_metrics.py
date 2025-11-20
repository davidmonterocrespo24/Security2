#!/usr/bin/env python3
"""
Script de Migración - ML Model Metrics
Crea la tabla ml_model_metrics en la base de datos
"""

import sys
from database.db_manager import DatabaseManager
from database.models import Base, MLModelMetrics
from sqlalchemy import create_engine, inspect
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'security.db')
DATABASE_URL = f'sqlite:///{DB_PATH}'


def migrate_ml_metrics():
    """Crear tabla de métricas ML si no existe"""
    print("="*70)
    print("MIGRACIÓN: ML Model Metrics")
    print("="*70)

    try:
        # Conectar a la base de datos
        print("\n[1/3] Conectando a la base de datos...")
        engine = create_engine(DATABASE_URL, echo=False)
        inspector = inspect(engine)
        print(f"  [OK] Conectado a: {DB_PATH}")

        # Verificar si la tabla ya existe
        print("\n[2/3] Verificando tabla ml_model_metrics...")
        if 'ml_model_metrics' in inspector.get_table_names():
            print("  [INFO] Tabla ml_model_metrics ya existe")
            print("  [INFO] Saltando creación")
        else:
            print("  [INFO] Tabla ml_model_metrics no existe")
            print("  [INFO] Creando tabla...")

            # Crear solo la tabla MLModelMetrics
            MLModelMetrics.__table__.create(engine)
            print("  [OK] Tabla ml_model_metrics creada")

        # Verificar creación
        print("\n[3/3] Verificando migración...")
        inspector = inspect(engine)

        if 'ml_model_metrics' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('ml_model_metrics')]
            print(f"  [OK] Tabla existe con {len(columns)} columnas")
            print(f"  [OK] Columnas: {', '.join(columns)}")
        else:
            print("  [ERROR] Tabla no fue creada")
            return False

        print("\n" + "="*70)
        print("[OK] MIGRACIÓN COMPLETADA")
        print("="*70)
        print("\nLa tabla ml_model_metrics está lista para almacenar:")
        print("  - Accuracy, Precision, Recall, F1-Score")
        print("  - ROC AUC")
        print("  - Matriz de confusión")
        print("  - Curvas ROC y Precision-Recall")
        print("  - Histórico de evaluaciones del modelo")
        print("\nPróximos pasos:")
        print("  1. Evaluar el modelo: python -c 'from modules.ml_metrics import MLMetrics; ...'")
        print("  2. Ver métricas en el dashboard: /ml-metrics/dashboard")

        return True

    except Exception as e:
        print(f"\n[ERROR] Error en migración: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = migrate_ml_metrics()
    sys.exit(0 if success else 1)
