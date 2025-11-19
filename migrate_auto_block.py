#!/usr/bin/env python3
"""
Script de Migración - Auto-Block Policies
Crea la tabla auto_block_policies y agrega política por defecto
"""

from database.models import Base, AutoBlockPolicy, engine
from database.db_manager import DatabaseManager
from datetime import datetime


def migrate_auto_block_table():
    """Crear tabla de políticas de auto-bloqueo"""
    print("="*70)
    print("MIGRACION: AUTO-BLOCK POLICIES")
    print("="*70)

    try:
        # Crear tabla
        print("\n[1/3] Creando tabla auto_block_policies...")
        Base.metadata.create_all(engine, tables=[AutoBlockPolicy.__table__])
        print("  [OK] Tabla creada exitosamente")

        # Verificar si ya existe una política por defecto
        db = DatabaseManager()
        session = db.get_session()

        existing = session.query(AutoBlockPolicy).filter_by(
            policy_name='default'
        ).first()

        if existing:
            print("\n[2/3] Política por defecto ya existe")
            print(f"  - ID: {existing.id}")
            print(f"  - Estado: {'Activa' if existing.enabled else 'Inactiva'}")
        else:
            print("\n[2/3] Creando política por defecto...")

            # Crear política por defecto (conservadora)
            default_policy = AutoBlockPolicy(
                policy_name='default',
                description='Política por defecto - Configuración conservadora para bloqueo automático',
                enabled=False,  # Deshabilitada por defecto (seguridad)
                min_ml_confidence=90.0,  # 90% confianza mínima
                min_threat_score=80.0,   # 80 puntos threat score mínimo
                min_severity='high',     # Solo high y critical
                min_events=5,            # Mínimo 5 eventos
                require_multiple_sources=True,  # Requiere 2+ fuentes
                default_block_duration=24,      # 24 horas
                permanent_block=False,          # No permanente
                apply_to_fail2ban=True,         # Aplicar en Fail2ban
                whitelist_enabled=True,         # Respetar whitelist
                exclude_internal_ips=True,      # No bloquear IPs internas
                total_blocks=0,
                created_at=datetime.utcnow(),
                created_by='system'
            )

            session.add(default_policy)
            session.commit()
            print("  [OK] Política 'default' creada")
            print(f"  - ID: {default_policy.id}")
            print(f"  - Min ML Confidence: {default_policy.min_ml_confidence}%")
            print(f"  - Min Threat Score: {default_policy.min_threat_score}")
            print(f"  - Min Severity: {default_policy.min_severity}")
            print(f"  - Estado: DESHABILITADA (activar manualmente)")

        # Crear política agresiva (opcional, deshabilitada)
        existing_aggressive = session.query(AutoBlockPolicy).filter_by(
            policy_name='aggressive'
        ).first()

        if not existing_aggressive:
            print("\n[3/3] Creando política 'aggressive' (opcional)...")

            aggressive_policy = AutoBlockPolicy(
                policy_name='aggressive',
                description='Política agresiva - Bloquea con criterios más permisivos',
                enabled=False,  # Deshabilitada por defecto
                min_ml_confidence=80.0,  # 80% confianza
                min_threat_score=60.0,   # 60 puntos
                min_severity='medium',   # medium, high, critical
                min_events=3,            # Mínimo 3 eventos
                require_multiple_sources=False,  # Una fuente suficiente
                default_block_duration=12,       # 12 horas
                permanent_block=False,
                apply_to_fail2ban=True,
                whitelist_enabled=True,
                exclude_internal_ips=True,
                total_blocks=0,
                created_at=datetime.utcnow(),
                created_by='system'
            )

            session.add(aggressive_policy)
            session.commit()
            print("  [OK] Política 'aggressive' creada")
            print(f"  - ID: {aggressive_policy.id}")
            print(f"  - Estado: DESHABILITADA")
        else:
            print("\n[3/3] Política 'aggressive' ya existe")

        session.close()

        print("\n" + "="*70)
        print("[OK] MIGRACION COMPLETADA")
        print("="*70)
        print("\nRECOMENDACIONES:")
        print("1. Revisar políticas en dashboard de Auto-Bloqueo")
        print("2. Ajustar parámetros según necesidades")
        print("3. Activar política deseada (default/aggressive/custom)")
        print("4. Monitorear bloqueos automáticos en logs")
        print("\nADVERTENCIA:")
        print("- Las políticas están DESHABILITADAS por defecto")
        print("- Activar solo después de revisar configuración")
        print("- Probar en modo dry-run primero")

        return True

    except Exception as e:
        print(f"\n[ERROR] Error durante migración: {e}")
        import traceback
        traceback.print_exc()
        return False


def show_current_policies():
    """Mostrar políticas actuales"""
    print("\n" + "="*70)
    print("POLITICAS ACTUALES")
    print("="*70)

    try:
        db = DatabaseManager()
        session = db.get_session()

        policies = session.query(AutoBlockPolicy).all()

        if not policies:
            print("\nNo hay políticas configuradas")
        else:
            for policy in policies:
                print(f"\n[{policy.id}] {policy.policy_name.upper()}")
                print(f"  Estado: {'✓ ACTIVA' if policy.enabled else '✗ INACTIVA'}")
                print(f"  Descripción: {policy.description}")
                print(f"  Criterios:")
                print(f"    - ML Confidence >= {policy.min_ml_confidence}%")
                print(f"    - Threat Score >= {policy.min_threat_score}")
                print(f"    - Severity >= {policy.min_severity}")
                print(f"    - Events >= {policy.min_events}")
                print(f"    - Multiple Sources: {'Sí' if policy.require_multiple_sources else 'No'}")
                print(f"  Bloqueo:")
                print(f"    - Duración: {policy.default_block_duration}h")
                print(f"    - Permanente: {'Sí' if policy.permanent_block else 'No'}")
                print(f"    - Fail2ban: {'Sí' if policy.apply_to_fail2ban else 'No'}")
                print(f"  Estadísticas:")
                print(f"    - Total bloqueadas: {policy.total_blocks}")

        session.close()

    except Exception as e:
        print(f"\n[ERROR] {e}")


if __name__ == '__main__':
    import sys

    # Ejecutar migración
    success = migrate_auto_block_table()

    if success:
        # Mostrar políticas actuales
        show_current_policies()
        sys.exit(0)
    else:
        sys.exit(1)
