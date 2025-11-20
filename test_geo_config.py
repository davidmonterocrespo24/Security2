"""
Script de prueba para el sistema de bloqueo geográfico
"""

from database.db_manager import DatabaseManager
from modules.geo_service import GeoLocationService

def test_geo_config():
    """Probar configuración geográfica"""

    print("=" * 70)
    print("PRUEBA DEL SISTEMA DE BLOQUEO GEOGRÁFICO")
    print("=" * 70)

    db = DatabaseManager()
    geo_service = GeoLocationService(db, use_api_fallback=True)

    # 1. Obtener configuración actual
    print("\n1. Configuración Actual:")
    print("-" * 70)
    config = db.get_geo_config()
    print(f"   Enabled: {config.get('enabled', False)}")
    print(f"   Mode: {config.get('mode', 'whitelist')}")
    print(f"   Countries: {config.get('countries', '[]')}")
    print(f"   Block Unknown: {config.get('block_unknown', False)}")

    # 2. Actualizar configuración de prueba
    print("\n2. Actualizando configuración de prueba...")
    print("-" * 70)
    success = db.update_geo_config(
        enabled=True,
        mode='blacklist',
        countries=['CN', 'RU'],  # Bloquear China y Rusia
        block_unknown=False,
        updated_by='test_script'
    )
    print(f"   Actualización: {'[OK] Exitosa' if success else '[ERROR] Falló'}")

    # 3. Verificar configuración actualizada
    print("\n3. Verificando configuración actualizada:")
    print("-" * 70)
    config = db.get_geo_config()
    print(f"   Enabled: {config.get('enabled', False)}")
    print(f"   Mode: {config.get('mode', 'whitelist')}")
    print(f"   Countries: {config.get('countries', '[]')}")
    print(f"   Block Unknown: {config.get('block_unknown', False)}")

    # 4. Probar con diferentes IPs
    print("\n4. Probando con diferentes IPs:")
    print("-" * 70)

    test_ips = [
        ('8.8.8.8', 'Google DNS (USA)'),
        ('114.114.114.114', 'DNS China'),
        ('77.88.8.8', 'Yandex DNS (Rusia)'),
        ('195.26.243.120', 'Tu IP'),
    ]

    for ip, description in test_ips:
        print(f"\n   IP: {ip} ({description})")

        # Obtener información del país
        geo_info = geo_service.get_country_info(ip)
        if geo_info:
            print(f"   País: {geo_info.get('country_name', 'Unknown')} ({geo_info.get('country_code', 'XX')})")

        # Verificar si está permitida
        allowed, reason = geo_service.is_country_allowed(ip)
        status = "[OK] PERMITIDA" if allowed else "[BLOCK] BLOQUEADA"
        print(f"   Estado: {status}")
        print(f"   Razón: {reason}")

    # 5. Restaurar configuración (desactivar filtro)
    print("\n5. Restaurando configuración (desactivando filtro)...")
    print("-" * 70)
    success = db.update_geo_config(
        enabled=False,
        mode='whitelist',
        countries=[],
        block_unknown=False,
        updated_by='test_script'
    )
    print(f"   Restauración: {'[OK] Exitosa' if success else '[ERROR] Falló'}")

    print("\n" + "=" * 70)
    print("PRUEBA COMPLETADA")
    print("=" * 70)

if __name__ == '__main__':
    test_geo_config()
