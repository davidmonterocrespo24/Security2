"""
Módulo de entrenamiento de Machine Learning
Funciones wrapper para task scheduler
"""

def retrain_model_task():
    """
    Re-entrenar el modelo ML con datos actualizados
    Función wrapper para ejecutar desde task scheduler

    Returns:
        dict: Resultado del entrenamiento
    """
    from database.db_manager import DatabaseManager
    from modules.ml_detector import MLTrafficDetector

    db = DatabaseManager()
    ml = MLTrafficDetector(db)

    print("[ML Training] Iniciando re-entrenamiento del modelo...")

    result = ml.train_model()

    if result['success']:
        return {
            'success': True,
            'message': f"Modelo ML re-entrenado. Accuracy: {result['accuracy']*100:.2f}%",
            'records_processed': result['training_samples'] + result['test_samples'],
            'records_created': 0,
            'accuracy': result['accuracy'],
            'training_samples': result['training_samples'],
            'test_samples': result['test_samples']
        }
    else:
        return {
            'success': False,
            'message': f"Error re-entrenando modelo: {result.get('error', 'Unknown error')}",
            'records_processed': 0,
            'records_created': 0
        }
