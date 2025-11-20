"""
Script para agregar geolocalización a eventos existentes
Usa la API pública ip-api.com para obtener país de cada IP
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database.db_manager import DatabaseManager
from database.models import SecurityEvent
from modules.geo_service import GeoLocationService
import time
import json

def add_geolocation_to_events():
    """Agregar geolocalización a todos los eventos que no la tienen"""

    db = DatabaseManager()
    geo_service = GeoLocationService(db, use_api_fallback=True)

    session = db.get_session()

    try:
        print("="*70, flush=True)
        print("AGREGANDO GEOLOCALIZACIÓN A EVENTOS EXISTENTES", flush=True)
        print("="*70, flush=True)

        # Obtener todos los eventos sin geolocalización
        events_without_geo = session.query(SecurityEvent).filter(
            (SecurityEvent.geo_location == None) | (SecurityEvent.geo_location == '')
        ).all()

        total = len(events_without_geo)
        print(f"\nEventos sin geolocalización: {total}")

        if total == 0:
            print("[OK] Todos los eventos ya tienen geolocalización")
            return

        # Obtener IPs únicas
        unique_ips = set()
        for event in events_without_geo:
            if event.source_ip:
                unique_ips.add(event.source_ip)

        print(f"IPs únicas a procesar: {len(unique_ips)}")
        print(f"\nEstimado: ~{len(unique_ips) * 0.5:.0f} segundos ({len(unique_ips) * 0.5 / 60:.1f} minutos)")
        print("\nIniciando procesamiento...\n")

        # Cache de geolocalizaciones por IP
        geo_cache = {}

        # Procesar cada IP única
        processed = 0
        errors = 0

        for ip in unique_ips:
            try:
                # Obtener geolocalización
                geo_info = geo_service.get_country_info(ip)

                if geo_info:
                    # Guardar en cache
                    geo_data = {
                        'country': geo_info.get('country_name', 'Unknown'),
                        'country_code': geo_info.get('country_code', 'XX'),
                        'city': geo_info.get('continent_name', 'Unknown'),
                        'latitude': 0,  # API doesn't provide coordinates
                        'longitude': 0
                    }
                    geo_cache[ip] = json.dumps(geo_data)

                    processed += 1

                    if processed % 10 == 0:
                        print(f"  [{processed}/{len(unique_ips)}] Procesadas {processed} IPs...")
                else:
                    geo_cache[ip] = None
                    errors += 1

                # Rate limiting - 45 req/min máximo
                time.sleep(1.5)  # ~40 req/min para estar seguros

            except Exception as e:
                print(f"  [ERROR] Error procesando IP {ip}: {e}")
                geo_cache[ip] = None
                errors += 1

        print(f"\n[OK] Geolocalizaciones obtenidas: {processed}")
        print(f"[WARN] Errores: {errors}")

        # Actualizar eventos con la geolocalización
        print("\nActualizando eventos en base de datos...")
        updated = 0

        for event in events_without_geo:
            if event.source_ip in geo_cache and geo_cache[event.source_ip]:
                event.geo_location = geo_cache[event.source_ip]
                updated += 1

                if updated % 100 == 0:
                    session.commit()
                    print(f"  [{updated}/{total}] Actualizados {updated} eventos...")

        # Commit final
        session.commit()

        print(f"\n{'='*70}")
        print(f"[OK] COMPLETADO")
        print(f"{'='*70}")
        print(f"  Eventos actualizados: {updated}/{total}")
        print(f"  IPs procesadas: {processed}/{len(unique_ips)}")
        print(f"  Errores: {errors}")
        print(f"\n[INFO] Los eventos ahora tienen información de país")
        print(f"[INFO] El mapa de amenazas debería mostrar datos")

    except Exception as e:
        session.rollback()
        print(f"\n[ERROR] Error en el proceso: {e}")
        import traceback
        traceback.print_exc()
    finally:
        session.close()


if __name__ == '__main__':
    add_geolocation_to_events()
