#!/usr/bin/env python3
"""
Test Script - Auto-Block API
Pruebas del API REST de auto-bloqueo
"""

import sys
import traceback
from database.db_manager import DatabaseManager
from modules.auto_blocker import AutoBlocker
from modules.fail2ban_manager import Fail2banManager


def test_api_components():
    """Probar componentes del API"""
    print("="*70)
    print("TEST: COMPONENTES DEL API DE AUTO-BLOQUEO")
    print("="*70)

    try:
        # 1. Inicializar managers
        print("\n[1/5] Inicializando managers...")
        db = DatabaseManager()
        fail2ban = Fail2banManager(db)
        auto_blocker = AutoBlocker(db, fail2ban)
        print("  [OK] Managers inicializados")

        # 2. Verificar políticas
        print("\n[2/5] Verificando políticas...")
        policies = db.get_auto_block_policies()
        print(f"  [OK] Políticas encontradas: {len(policies)}")
        for policy in policies:
            print(f"    - {policy['policy_name']}: {'ACTIVA' if policy['enabled'] else 'INACTIVA'}")

        # 3. Obtener política activa
        print("\n[3/5] Obteniendo política activa...")
        active_policy = db.get_active_auto_block_policy()
        if active_policy:
            print(f"  [OK] Política activa: {active_policy['policy_name']}")
        else:
            print("  [INFO] No hay ninguna política activa")

        # 4. Obtener estadísticas
        print("\n[4/5] Obteniendo estadísticas...")
        stats = auto_blocker.get_auto_block_stats(hours_back=24)
        print(f"  [OK] Estadísticas obtenidas:")
        print(f"    - Evaluadas: {stats.get('total_evaluated', 0)}")
        print(f"    - Bloqueadas: {stats.get('total_blocked', 0)}")
        print(f"    - Tasa de bloqueo: {stats.get('block_rate', 0):.1f}%")

        # 5. Simular creación de política
        print("\n[5/5] Simulando creación de política...")
        test_policy_name = 'test_api_policy'

        # Verificar si ya existe
        existing = next((p for p in policies if p['policy_name'] == test_policy_name), None)
        if existing:
            print(f"  [INFO] Política de prueba ya existe (ID: {existing['id']})")
            print(f"  [INFO] Eliminando política existente...")
            db.delete_auto_block_policy(existing['id'])

        # Crear política de prueba
        policy_dict = db.create_auto_block_policy(
            policy_name=test_policy_name,
            description='Política de prueba para API',
            enabled=False,
            min_ml_confidence=75.0,
            min_threat_score=50.0,
            min_severity='medium',
            min_events=2,
            created_by='test_script'
        )
        print(f"  [OK] Política de prueba creada (ID: {policy_dict['id']})")

        # Actualizar política
        db.update_auto_block_policy(
            policy_dict['id'],
            description='Política de prueba actualizada',
            updated_by='test_script'
        )
        print(f"  [OK] Política actualizada")

        # Eliminar política de prueba
        db.delete_auto_block_policy(policy_dict['id'])
        print(f"  [OK] Política de prueba eliminada")

        print("\n" + "="*70)
        print("[OK] TODOS LOS TESTS PASARON")
        print("="*70)
        print("\nRESUMEN:")
        print(f"  - Managers: [OK] Funcionando")
        print(f"  - Politicas: [OK] {len(policies)} encontradas")
        print(f"  - Estadisticas: [OK] Disponibles")
        print(f"  - CRUD: [OK] Funcionando")
        print("\nPRÓXIMOS PASOS:")
        print("  1. Iniciar servidor Flask: python app.py")
        print("  2. Probar endpoints del API:")
        print("     - GET  /auto-block/api/policies")
        print("     - GET  /auto-block/api/policies/active")
        print("     - POST /auto-block/api/policies/<id>/toggle")
        print("     - GET  /auto-block/api/stats")
        print("     - POST /auto-block/api/process (dry-run)")
        print("  3. Crear dashboard frontend")

        return True

    except Exception as e:
        print(f"\n[ERROR] Test falló: {e}")
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = test_api_components()
    sys.exit(0 if success else 1)
