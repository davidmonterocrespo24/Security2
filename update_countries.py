#!/usr/bin/env python3
"""
Script para actualizar la información de país en predicciones ML existentes
Usa múltiples APIs con fallback y mejor manejo de rate limiting
"""

from database.db_manager import DatabaseManager
from database.models import MLPrediction
import requests
import time


def get_country_from_apis(ip, timeout=5):
    """
    Intenta obtener país de IP usando múltiples APIs gratuitas
    Returns: (country_name, country_code) o (None, None) si falla
    """

    # API 1: ip-api.com (sin límite si usamos http y esperamos 1 seg)
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=country,countryCode', timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') != 'fail':
                country = data.get('country')
                code = data.get('countryCode')
                if country and code:
                    return (country, code)
    except:
        pass

    # API 2: ipapi.co (backup, limitado)
    try:
        time.sleep(2)  # Esperar más entre llamadas
        response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            country = data.get('country_name')
            code = data.get('country_code')
            if country and code:
                return (country, code)
    except:
        pass

    # API 3: ipwhois.app (sin límite para uso razonable)
    try:
        time.sleep(1)
        response = requests.get(f'http://ipwhois.app/json/{ip}', timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                country = data.get('country')
                code = data.get('country_code')
                if country and code:
                    return (country, code)
    except:
        pass

    return (None, None)


def update_ml_predictions_countries(batch_size=10, delay=2):
    """
    Actualizar países en predicciones ML existentes

    Args:
        batch_size: Número de IPs a procesar antes de hacer commit
        delay: Segundos de espera entre consultas
    """
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

        for idx, pred in enumerate(predictions, 1):
            ip = pred.ip_address

            print(f"\n[{idx}/{len(predictions)}] Procesando {ip}...", end=" ")

            # Skip IPs privadas
            if any(ip.startswith(skip) for skip in skip_ips):
                pred.country = 'Private Network (LAN)'
                pred.country_code = 'LAN'
                updated_count += 1
                print(f"[OK] -> {pred.country}")
                continue

            # Consultar APIs con fallback
            country_name, country_code = get_country_from_apis(ip)

            if country_name and country_code:
                pred.country = f"{country_name} ({country_code})"
                pred.country_code = country_code
                updated_count += 1
                print(f"[OK] -> {pred.country}")
            else:
                failed_count += 1
                print(f"[SKIP] -> No se pudo obtener información")

            # Hacer commit cada batch_size elementos
            if idx % batch_size == 0:
                session.commit()
                print(f"\n  -> Guardando progreso ({updated_count} actualizadas)...")
                time.sleep(delay)  # Pausa más larga después de cada lote

            # Rate limit entre consultas
            time.sleep(delay)

        # Commit final
        session.commit()

        print("\n" + "="*60)
        print(f"[OK] ACTUALIZACION COMPLETADA")
        print("="*60)
        print(f"  - Actualizadas: {updated_count}")
        print(f"  - Fallidas: {failed_count}")
        print(f"  - Total: {len(predictions)}")
        print(f"  - Éxito: {(updated_count/len(predictions)*100):.1f}%")

    except Exception as e:
        session.rollback()
        print(f"\n[ERROR] Error durante actualización: {e}")
        import traceback
        traceback.print_exc()
    finally:
        session.close()


if __name__ == '__main__':
    update_ml_predictions_countries()
