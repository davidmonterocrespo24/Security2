#!/usr/bin/env python3
"""
Script de prueba para el sistema de alertas
"""

from database.db_manager import DatabaseManager
from database.models import AlertChannel, AlertRule, AlertLog
from modules.alert_manager import AlertManager
from datetime import datetime
import json
import os


def test_database_models():
    """Verificar que los modelos existen en la base de datos"""
    print("\n" + "="*60)
    print("TEST 1: VERIFICAR MODELOS DE BASE DE DATOS")
    print("="*60)

    db = DatabaseManager()
    session = db.get_session()

    try:
        # Verificar canales
        channels = session.query(AlertChannel).all()
        print(f"\n[OK] Canales encontrados: {len(channels)}")
        for channel in channels:
            print(f"  - {channel.channel_name} ({channel.channel_type}) - {'Habilitado' if channel.is_enabled else 'Deshabilitado'}")

        # Verificar reglas
        rules = session.query(AlertRule).all()
        print(f"\n[OK] Reglas encontradas: {len(rules)}")
        for rule in rules:
            print(f"  - {rule.rule_name} ({rule.rule_type}) - {'Activa' if rule.is_enabled else 'Inactiva'}")

        # Verificar logs
        logs_count = session.query(AlertLog).count()
        print(f"\n[OK] Logs de alertas en BD: {logs_count}")

        return True
    except Exception as e:
        print(f"\n[ERROR] Error al verificar modelos: {e}")
        return False
    finally:
        session.close()


def test_alert_manager():
    """Probar funcionalidad básica del AlertManager"""
    print("\n" + "="*60)
    print("TEST 2: VERIFICAR ALERT MANAGER")
    print("="*60)

    db = DatabaseManager()
    alert_manager = AlertManager(db)

    # Test 1: Verificar inicialización
    print("\n[OK] AlertManager inicializado correctamente")

    # Test 2: Verificar método send_email (sin enviar realmente)
    print("\n[INFO] Verificando configuracion SMTP...")

    smtp_user = os.getenv('SMTP_USER', '')
    if smtp_user:
        print(f"  [OK] SMTP_USER configurado: {smtp_user}")
    else:
        print("  [WARNING] SMTP_USER no configurado en .env")

    return True


def test_alert_processing():
    """Probar el procesamiento de alertas"""
    print("\n" + "="*60)
    print("TEST 3: PROCESAMIENTO DE ALERTAS")
    print("="*60)

    db = DatabaseManager()
    alert_manager = AlertManager(db)

    # Crear evento de prueba
    test_event = {
        'type': 'ml_prediction',
        'severity': 'HIGH',
        'ip': '192.168.1.100',
        'confidence': 95,
        'ml_confidence': 0.95,
        'reason': 'Actividad sospechosa detectada por ML',
        'timestamp': datetime.utcnow().isoformat(),
        'country': 'Test Country'
    }

    print("\n[INFO] Procesando evento de prueba...")
    print(f"  Tipo: {test_event['type']}")
    print(f"  Severidad: {test_event['severity']}")
    print(f"  IP: {test_event['ip']}")
    print(f"  Confianza: {test_event['confidence']}%")

    try:
        result = alert_manager.process_alert(test_event)

        if result['alerts_sent'] > 0:
            print(f"\n[OK] Alerta procesada: {result['alerts_sent']} alerta(s) enviada(s)")
        else:
            print(f"\n[INFO] No se enviaron alertas (normal si no hay canales habilitados)")

        if result.get('errors'):
            print(f"  Errores: {len(result['errors'])}")
            for error in result['errors']:
                print(f"    - {error}")
        else:
            print("  Sin errores en procesamiento")

        return True
    except Exception as e:
        print(f"\n[ERROR] Error al procesar alerta: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_zeek_integration():
    """Verificar integración con Zeek"""
    print("\n" + "="*60)
    print("TEST 4: INTEGRACION CON ZEEK")
    print("="*60)

    try:
        from modules.zeek_ml_integration import ZeekMLIntegration

        db = DatabaseManager()
        zeek_integration = ZeekMLIntegration(db)

        if zeek_integration.alert_manager:
            print("\n[OK] AlertManager integrado en ZeekMLIntegration")
        else:
            print("\n[WARNING] AlertManager no inicializado en ZeekMLIntegration")

        return True
    except Exception as e:
        print(f"\n[ERROR] Error al verificar integración Zeek: {e}")
        return False


def test_ml_integration():
    """Verificar integración con ML"""
    print("\n" + "="*60)
    print("TEST 5: INTEGRACION CON ML")
    print("="*60)

    try:
        from modules.ml_detector import MLTrafficDetector
        from modules.geo_service import GeoLocationService

        db = DatabaseManager()
        geo_service = GeoLocationService(db)
        ml_detector = MLTrafficDetector(db, geo_service=geo_service)

        if ml_detector.alert_manager:
            print("\n[OK] AlertManager integrado en MLTrafficDetector")
        else:
            print("\n[WARNING] AlertManager no inicializado en MLTrafficDetector")

        return True
    except Exception as e:
        print(f"\n[ERROR] Error al verificar integración ML: {e}")
        return False


def test_fail2ban_integration():
    """Verificar integración con Fail2ban"""
    print("\n" + "="*60)
    print("TEST 6: INTEGRACION CON FAIL2BAN")
    print("="*60)

    try:
        from modules.fail2ban_manager import Fail2banManager

        db = DatabaseManager()
        f2b_manager = Fail2banManager(db)

        if f2b_manager.alert_manager:
            print("\n[OK] AlertManager integrado en Fail2banManager")
        else:
            print("\n[WARNING] AlertManager no inicializado en Fail2banManager")

        return True
    except Exception as e:
        print(f"\n[ERROR] Error al verificar integración Fail2ban: {e}")
        return False


def main():
    """Ejecutar todos los tests"""
    print("\n" + "="*60)
    print("SISTEMA DE PRUEBAS - ALERTAS Y NOTIFICACIONES")
    print("="*60)

    tests = [
        ("Modelos de Base de Datos", test_database_models),
        ("Alert Manager", test_alert_manager),
        ("Procesamiento de Alertas", test_alert_processing),
        ("Integracion Zeek", test_zeek_integration),
        ("Integracion ML", test_ml_integration),
        ("Integracion Fail2ban", test_fail2ban_integration)
    ]

    results = []

    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n[ERROR] Test '{test_name}' fallo: {e}")
            results.append((test_name, False))

    # Resumen
    print("\n" + "="*60)
    print("RESUMEN DE PRUEBAS")
    print("="*60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    print(f"\nPruebas pasadas: {passed}/{total}")
    print("\nDetalle:")
    for test_name, result in results:
        status = "[OK]" if result else "[FAIL]"
        print(f"  {status} {test_name}")

    if passed == total:
        print("\n[OK] TODOS LOS TESTS PASARON!")
    else:
        print(f"\n[WARNING] {total - passed} test(s) fallaron")

    print("="*60 + "\n")


if __name__ == '__main__':
    main()
