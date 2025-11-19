#!/usr/bin/env python3
"""
Script de prueba para verificar el servicio de geolocalización con APIs públicas
"""

from database.db_manager import DatabaseManager
from modules.geo_service import GeoLocationService

def test_geo_service():
    """Probar el servicio de geolocalización con diferentes IPs"""

    print("="*70)
    print("PRUEBA DE SERVICIO DE GEOLOCALIZACIÓN")
    print("="*70)

    # Inicializar servicio
    db = DatabaseManager()
    geo_service = GeoLocationService(db, use_api_fallback=True)

    # IPs de prueba (públicas conocidas)
    test_ips = [
        ('8.8.8.8', 'Google DNS - Estados Unidos'),
        ('1.1.1.1', 'Cloudflare DNS - Estados Unidos/Australia'),
        ('91.92.133.55', 'IP de ejemplo 1'),
        ('103.143.11.175', 'IP de ejemplo 2'),
        ('192.168.1.1', 'IP privada'),
        ('invalid.ip', 'IP inválida'),
    ]

    print(f"\n[INFO] Probando {len(test_ips)} direcciones IP...\n")

    successful = 0
    failed = 0

    for ip, description in test_ips:
        print(f"[TEST] {ip} ({description})")

        try:
            result = geo_service.get_country_info(ip)

            if result:
                country_name = result.get('country_name', 'Unknown')
                country_code = result.get('country_code', 'XX')

                print(f"  [OK] Pais: {country_name} ({country_code})")
                successful += 1
            else:
                print(f"  [FAIL] No se pudo obtener informacion")
                failed += 1

        except Exception as e:
            print(f"  [ERROR] {e}")
            failed += 1

        print()

    # Resumen
    print("="*70)
    print("RESUMEN DE PRUEBAS")
    print("="*70)
    print(f"[OK] Exitosas: {successful}/{len(test_ips)}")
    print(f"[FAIL] Fallidas: {failed}/{len(test_ips)}")
    print(f"[INFO] Tasa de exito: {(successful/len(test_ips)*100):.1f}%")

    # Verificar caché
    cache_size = geo_service.get_cache_size()
    print(f"\n[CACHE] IPs en cache: {cache_size}")

    print("\n" + "="*70)
    print("[OK] PRUEBA COMPLETADA")
    print("="*70)


if __name__ == '__main__':
    test_geo_service()
