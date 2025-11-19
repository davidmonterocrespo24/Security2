#!/usr/bin/env python3
"""
Script para actualizar la información de país en predicciones ML existentes
"""

from database.db_manager import DatabaseManager
from database.models import MLPrediction
import requests
import time


def update_ml_predictions_countries():
    """Actualizar países en predicciones ML existentes"""
    print("="*60)
    print("ACTUALIZACION DE PAISES EN ML PREDICTIONS")
    print("="*60)

    db = DatabaseManager()
    session = db.get_session()

    try:
        # Obtener todas las predicciones con país Unknown
        predictions = session.query(MLPrediction).filter(
            (MLPrediction.country == 'Unknown') | (MLPrediction.country == None)
        ).all()

        print(f"\n[INFO] Encontradas {len(predictions)} predicciones sin país")

        if len(predictions) == 0:
            print("[OK] Todas las predicciones ya tienen país asignado")
            return

        updated_count = 0
        failed_count = 0
        skip_ips = ['192.168', '10.', '172.']  # IPs privadas

        for pred in predictions:
            ip = pred.ip_address

            # Skip IPs privadas
            if any(ip.startswith(skip) for skip in skip_ips):
                pred.country = 'Private Network (LAN)'
                pred.country_code = 'LAN'
                updated_count += 1
                print(f"  [OK] {ip} -> {pred.country}")
                continue

            # Consultar API pública ipapi.co (gratis, sin key)
            try:
                response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    country_name = data.get('country_name', 'Unknown')
                    country_code = data.get('country_code', 'XX')

                    if country_name and country_name != 'Unknown':
                        pred.country = f"{country_name} ({country_code})"
                        pred.country_code = country_code
                        updated_count += 1
                        print(f"  [OK] {ip} -> {pred.country}")
                    else:
                        failed_count += 1
                        print(f"  [SKIP] {ip} -> Sin información geográfica")
                else:
                    failed_count += 1
                    print(f"  [SKIP] {ip} -> API error {response.status_code}")

                # Rate limit: esperar 1 segundo entre consultas
                time.sleep(1)

            except requests.exceptions.Timeout:
                failed_count += 1
                print(f"  [SKIP] {ip} -> Timeout")
            except Exception as e:
                failed_count += 1
                print(f"  [ERROR] {ip} -> {e}")

        # Commit de cambios
        session.commit()

        print("\n" + "="*60)
        print(f"[OK] ACTUALIZACION COMPLETADA")
        print("="*60)
        print(f"  - Actualizadas: {updated_count}")
        print(f"  - Fallidas: {failed_count}")
        print(f"  - Total: {len(predictions)}")

    except Exception as e:
        session.rollback()
        print(f"\n[ERROR] Error durante actualización: {e}")
        import traceback
        traceback.print_exc()
    finally:
        session.close()


if __name__ == '__main__':
    update_ml_predictions_countries()
