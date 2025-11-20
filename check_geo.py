from database.db_manager import DatabaseManager
from database.models import SecurityEvent

db = DatabaseManager()
session = db.get_session()

events_with_geo = session.query(SecurityEvent).filter(
    SecurityEvent.geo_location != None,
    SecurityEvent.geo_location != ''
).count()

total_events = session.query(SecurityEvent).count()

print(f"Events with geolocation: {events_with_geo}/{total_events}")

session.close()
