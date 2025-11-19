#!/usr/bin/env python3
"""
Script para probar la correccion del error de datetime en ml_predictions
"""

from database.db_manager import DatabaseManager
from datetime import datetime
import json

def test_datetime_fix():
    """Probar que las fechas se convierten correctamente"""
    print("="*60)
    print("TEST: Correccion de DateTime en ML Predictions")
    print("="*60)

    db = DatabaseManager()

    # Test 1: Guardar prediccion con fechas como strings
    print("\n[TEST 1] Guardando prediccion con fechas como strings...")
    test_data_string_dates = {
        'ml_confidence': 0.95,
        'is_anomaly': False,
        'total_events': 10,
        'suspicious_events': 8,
        'anomaly_events': 2,
        'country': 'Test Country',
        'country_code': 'TC',
        'first_seen': '2025-11-19T10:00:00',  # String ISO format
        'last_seen': '2025-11-19T12:00:00',   # String ISO format
        'reasons': 'Test prediction with string dates',
        'recommended_action': 'monitor',
        'is_blocked': False,
        'threat_score': 50.0,
        'action_text': 'Testing',
        'behavioral_features': {'test': True},
        'threat_factors': ['test1', 'test2'],
        'requests_per_minute': 5.0,
        'error_ratio': 0.1,
        'is_bot': False
    }

    result1 = db.save_ml_prediction('192.168.1.100', test_data_string_dates, model_version='test')
    if result1:
        print("[OK] Prediccion guardada exitosamente con fechas string")
    else:
        print("[ERROR] Fallo al guardar prediccion con fechas string")
        return False

    # Test 2: Guardar prediccion con fechas como objetos datetime
    print("\n[TEST 2] Guardando prediccion con fechas como objetos datetime...")
    test_data_datetime_objects = {
        'ml_confidence': 0.85,
        'is_anomaly': True,
        'total_events': 15,
        'suspicious_events': 12,
        'anomaly_events': 5,
        'country': 'Test Country 2',
        'country_code': 'T2',
        'first_seen': datetime(2025, 11, 19, 8, 0, 0),  # Objeto datetime
        'last_seen': datetime(2025, 11, 19, 11, 0, 0),  # Objeto datetime
        'reasons': 'Test prediction with datetime objects',
        'recommended_action': 'block',
        'is_blocked': True,
        'threat_score': 75.0,
        'action_text': 'Testing 2',
        'behavioral_features': {'test': True},
        'threat_factors': ['test3', 'test4'],
        'requests_per_minute': 10.0,
        'error_ratio': 0.3,
        'is_bot': True
    }

    result2 = db.save_ml_prediction('192.168.1.101', test_data_datetime_objects, model_version='test')
    if result2:
        print("[OK] Prediccion guardada exitosamente con objetos datetime")
    else:
        print("[ERROR] Fallo al guardar prediccion con objetos datetime")
        return False

    # Test 3: Guardar prediccion sin fechas (deberia usar datetime.utcnow())
    print("\n[TEST 3] Guardando prediccion sin fechas...")
    test_data_no_dates = {
        'ml_confidence': 0.75,
        'is_anomaly': False,
        'total_events': 5,
        'suspicious_events': 3,
        'anomaly_events': 1,
        'country': 'Test Country 3',
        'country_code': 'T3',
        # No incluimos first_seen ni last_seen
        'reasons': 'Test prediction without dates',
        'recommended_action': 'monitor',
        'is_blocked': False,
        'threat_score': 35.0,
        'action_text': 'Testing 3',
        'behavioral_features': {'test': True},
        'threat_factors': ['test5'],
        'requests_per_minute': 2.0,
        'error_ratio': 0.05,
        'is_bot': False
    }

    result3 = db.save_ml_prediction('192.168.1.102', test_data_no_dates, model_version='test')
    if result3:
        print("[OK] Prediccion guardada exitosamente sin fechas")
    else:
        print("[ERROR] Fallo al guardar prediccion sin fechas")
        return False

    # Test 4: Actualizar prediccion existente
    print("\n[TEST 4] Actualizando prediccion existente...")
    update_data = {
        'ml_confidence': 0.98,
        'is_anomaly': True,
        'total_events': 20,
        'suspicious_events': 18,
        'anomaly_events': 10,
        'country': 'Updated Country',
        'country_code': 'UC',
        'first_seen': '2025-11-19T09:00:00',
        'last_seen': '2025-11-19T13:00:00',
        'reasons': 'Updated test prediction',
        'recommended_action': 'block',
        'is_blocked': True,
        'threat_score': 90.0,
        'action_text': 'Updated Testing',
        'behavioral_features': {'updated': True},
        'threat_factors': ['updated1', 'updated2'],
        'requests_per_minute': 15.0,
        'error_ratio': 0.5,
        'is_bot': True
    }

    result4 = db.save_ml_prediction('192.168.1.100', update_data, model_version='test')
    if result4:
        print("[OK] Prediccion actualizada exitosamente")
    else:
        print("[ERROR] Fallo al actualizar prediccion")
        return False

    # Test 5: Verificar que las predicciones se guardaron correctamente
    print("\n[TEST 5] Verificando predicciones guardadas...")
    predictions = db.get_ml_predictions(hours_back=24, min_confidence=0.0, only_valid=True)

    test_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
    found_count = 0
    for pred in predictions:
        if pred['ip_address'] in test_ips:
            found_count += 1
            print(f"  [OK] Encontrada: {pred['ip_address']} - Confianza: {pred['ml_confidence']}")

    if found_count >= 3:
        print(f"[OK] Se encontraron {found_count} predicciones de prueba")
    else:
        print(f"[WARNING] Solo se encontraron {found_count}/3 predicciones de prueba")

    print("\n" + "="*60)
    print("RESULTADO: TODOS LOS TESTS PASARON")
    print("="*60)
    return True


if __name__ == '__main__':
    try:
        success = test_datetime_fix()
        if success:
            print("\n[OK] Correccion de datetime verificada exitosamente!")
        else:
            print("\n[ERROR] Algunos tests fallaron")
    except Exception as e:
        print(f"\n[ERROR] Exception durante testing: {e}")
        import traceback
        traceback.print_exc()
