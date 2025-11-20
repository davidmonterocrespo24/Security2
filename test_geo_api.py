"""
Test de las APIs de configuración geográfica
"""

from database.db_manager import DatabaseManager
from database.models import SecurityEvent
import json

db = DatabaseManager()

print("=" * 70)
print("TEST DE APIS DE CONFIGURACIÓN GEOGRÁFICA")
print("=" * 70)

# 1. Test get_geo_config
print("\n1. get_geo_config():")
print("-" * 70)
config = db.get_geo_config()
print(f"Config: {config}")

# 2. Test available countries
print("\n2. Países disponibles en eventos:")
print("-" * 70)
session = db.get_session()

try:
    events = session.query(SecurityEvent.geo_location).filter(
        SecurityEvent.geo_location != None,
        SecurityEvent.geo_location != ''
    ).limit(10).all()

    print(f"Total eventos con geo: {len(events)}")

    countries_set = set()
    for (geo_location,) in events:
        if geo_location:
            try:
                geo_data = json.loads(geo_location)
                country_code = geo_data.get('country_code', 'XX')
                country_name = geo_data.get('country', 'Unknown')

                if country_code not in countries_set:
                    countries_set.add(country_code)
                    print(f"  - {country_name} ({country_code})")
            except Exception as e:
                print(f"  Error parseando geo_location: {e}")

    print(f"\nTotal países únicos: {len(countries_set)}")

finally:
    session.close()

# 3. Test statistics
print("\n3. Estadísticas por país:")
print("-" * 70)
session = db.get_session()

try:
    events = session.query(SecurityEvent).filter(
        SecurityEvent.geo_location != None,
        SecurityEvent.geo_location != ''
    ).limit(100).all()

    country_stats = {}

    for event in events:
        if event.geo_location:
            try:
                geo_data = json.loads(event.geo_location)
                country_code = geo_data.get('country_code', 'XX')
                country_name = geo_data.get('country', 'Unknown')

                if country_code not in country_stats:
                    country_stats[country_code] = {
                        'name': country_name,
                        'count': 0
                    }

                country_stats[country_code]['count'] += 1
            except:
                continue

    # Ordenar por count
    sorted_countries = sorted(country_stats.items(), key=lambda x: x[1]['count'], reverse=True)

    for code, data in sorted_countries[:10]:
        print(f"  {data['name']:20s} ({code}): {data['count']:3d} eventos")

finally:
    session.close()

print("\n" + "=" * 70)
print("TEST COMPLETADO")
print("=" * 70)
