# Sistema de Filtrado Geográfico

Sistema de seguridad basado en geolocalización de IPs que permite controlar el acceso según el país de origen.

## Características

### 1. Geolocalización de IPs
- Identificación automática del país de origen mediante base de datos GeoLite2
- Soporte para IPv4 e IPv6
- Detección de IPs privadas/locales
- Cache para mejor rendimiento

### 2. Modos de Filtrado

**Modo Whitelist (Permitir solo países específicos)**
- Solo permite acceso desde países en la lista configurada
- Bloquea automáticamente el resto del mundo
- Ideal para servicios regionales o locales

**Modo Blacklist (Bloquear países específicos)**
- Permite acceso desde cualquier país excepto los de la lista
- Útil para bloquear regiones con alto índice de ataques
- Más permisivo que el modo whitelist

### 3. Opciones Avanzadas

- **Bloquear IPs desconocidas**: Opción para bloquear IPs sin información geográfica
- **Permitir IPs privadas**: Las IPs locales/privadas siempre son permitidas
- **Logs y auditoría**: Todos los bloqueos geo se registran en eventos de seguridad

## Instalación

### 1. Instalar librerías de Python

```bash
pip install geoip2==4.7.0 maxminddb==2.6.2
```

### 2. Descargar base de datos GeoLite2

MaxMind requiere una cuenta gratuita. Dos opciones:

#### Opción A: Descarga automática con script

```bash
# 1. Obtener License Key gratuita
# Crea una cuenta en: https://www.maxmind.com/en/geolite2/signup
# Genera una key en: https://www.maxmind.com/en/accounts/current/license-key

# 2. Configurar variable de entorno
export MAXMIND_LICENSE_KEY='tu_license_key_aqui'

# 3. Ejecutar script de descarga
python scripts/download_geoip_db.py

# O pasar la key directamente:
python scripts/download_geoip_db.py TU_LICENSE_KEY
```

#### Opción B: Descarga manual

```bash
# 1. Descarga desde: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# 2. Extrae el archivo GeoLite2-Country.mmdb
# 3. Muévelo a: data/GeoLite2-Country.mmdb
```

### 3. Verificar instalación

```bash
# Verificar que la base de datos existe
ls -lh data/GeoLite2-Country.mmdb

# Probar en Python
python -c "from modules.geo_service import GeoLocationService; print('✅ OK')"
```

## Uso

### 1. Configuración Básica

```python
from database.db_manager import DatabaseManager
from modules.geo_service import GeoLocationService

# Inicializar servicios
db = DatabaseManager()
geo = GeoLocationService(db)

# Activar filtrado geográfico en modo whitelist
db.update_geo_config(
    enabled=True,
    mode='whitelist',
    countries=['AR', 'CL', 'UY', 'PE'],  # Solo permitir estos países
    block_unknown=False
)
```

### 2. Verificar IP

```python
# Verificar si una IP está permitida
allowed, reason = geo.is_country_allowed('200.123.45.67')

if allowed:
    print(f"✅ Acceso permitido: {reason}")
else:
    print(f"❌ Acceso bloqueado: {reason}")
```

### 3. Obtener Información de País

```python
# Obtener información detallada del país
info = geo.get_country_info('8.8.8.8')
print(info)
# {
#     'country_code': 'US',
#     'country_name': 'United States',
#     'continent_code': 'NA',
#     'continent_name': 'North America'
# }
```

### 4. Estadísticas por País

```python
# Obtener estadísticas de acceso por país
stats = geo.get_country_statistics(limit_days=30)

for country in stats[:10]:
    print(f"{country['country_name']} ({country['country_code']}): "
          f"{country['total_events']} eventos, "
          f"{country['malicious_percentage']:.1f}% maliciosos")
```

## API Endpoints (Cuando se implementen)

### GET /api/geo/config
Obtener configuración actual

```json
{
  "enabled": true,
  "mode": "whitelist",
  "countries": ["AR", "CL", "UY"],
  "block_unknown": false
}
```

### POST /api/geo/config
Actualizar configuración

```json
{
  "enabled": true,
  "mode": "blacklist",
  "countries": ["CN", "RU"],
  "block_unknown": true
}
```

### POST /api/geo/countries/add
Agregar país a la lista

```json
{
  "country_code": "BR"
}
```

### DELETE /api/geo/countries/remove
Remover país de la lista

```json
{
  "country_code": "BR"
}
```

### GET /api/geo/stats
Obtener estadísticas por país

```json
[
  {
    "country_code": "AR",
    "country_name": "Argentina",
    "total_events": 523,
    "unique_ips": 45,
    "malicious_events": 23,
    "malicious_percentage": 4.4
  }
]
```

## Códigos de País (ISO 3166-1 alpha-2)

### Sudamérica
- `AR` - Argentina
- `BO` - Bolivia
- `BR` - Brasil
- `CL` - Chile
- `CO` - Colombia
- `EC` - Ecuador
- `GY` - Guyana
- `PE` - Perú
- `PY` - Paraguay
- `SR` - Surinam
- `UY` - Uruguay
- `VE` - Venezuela

### Norteamérica
- `CA` - Canadá
- `MX` - México
- `US` - Estados Unidos

### Europa
- `ES` - España
- `FR` - Francia
- `DE` - Alemania
- `IT` - Italia
- `GB` - Reino Unido
- `PT` - Portugal

### Asia
- `CN` - China
- `JP` - Japón
- `KR` - Corea del Sur
- `IN` - India
- `RU` - Rusia

**Ver lista completa**: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2

## Ejemplos de Uso

### Ejemplo 1: Servicio solo para Argentina

```python
db.update_geo_config(
    enabled=True,
    mode='whitelist',
    countries=['AR'],
    block_unknown=True  # Bloquear IPs sin país identificado
)
```

### Ejemplo 2: Bloquear países con alto nivel de amenazas

```python
# Lista de países comúnmente asociados con ataques
high_risk_countries = ['CN', 'RU', 'KP', 'IR']

db.update_geo_config(
    enabled=True,
    mode='blacklist',
    countries=high_risk_countries,
    block_unknown=False  # Permitir IPs no identificadas
)
```

### Ejemplo 3: Servicio regional (Cono Sur)

```python
db.update_geo_config(
    enabled=True,
    mode='whitelist',
    countries=['AR', 'CL', 'UY', 'PY', 'BR'],
    block_unknown=False
)
```

### Ejemplo 4: Agregar/remover países dinámicamente

```python
# Agregar un país
db.add_country_to_filter('ES', updated_by='admin')

# Remover un país
db.remove_country_from_filter('ES', updated_by='admin')
```

## Integración con Flask Middleware

El sistema incluye middleware que verifica automáticamente cada request antes de permitir el acceso:

```python
from flask import Flask, request, jsonify

@app.before_request
def check_geo_access():
    """Middleware para verificar acceso geográfico"""

    # Obtener IP del cliente
    client_ip = request.remote_addr

    # Verificar si el filtrado geo está activo
    geo_config = db.get_geo_config()
    if not geo_config.get('enabled'):
        return None  # Filtrado desactivado, permitir acceso

    # Verificar si el país está permitido
    allowed, reason = geo.is_country_allowed(client_ip)

    if not allowed:
        # Registrar evento de seguridad
        db.log_security_event(
            event_type='geo_block',
            severity='medium',
            source_ip=client_ip,
            details=reason
        )

        # Retornar error 403
        return jsonify({
            'error': 'Access denied',
            'reason': 'Geographic restriction',
            'details': reason
        }), 403

    return None  # Acceso permitido
```

## Monitoreo y Logs

### Ver eventos de bloqueo geográfico

```python
# Obtener eventos de bloqueo geo
events = db.get_security_events(event_type='geo_block', limit=100)

for event in events:
    print(f"{event['timestamp']}: {event['source_ip']} - {event['details']}")
```

### Estadísticas de países bloqueados

```python
# Analizar patrones de acceso por país
stats = geo.get_country_statistics(limit_days=7)

print("\n📊 Top 10 países con más actividad:")
for i, country in enumerate(stats[:10], 1):
    print(f"{i}. {country['country_name']}: "
          f"{country['total_events']} eventos "
          f"({country['malicious_percentage']:.1f}% maliciosos)")
```

## Consideraciones de Seguridad

### Ventajas
- ✅ Reduce superficie de ataque bloqueando regiones no necesarias
- ✅ Protección contra botnets geográficamente distribuidos
- ✅ Cumplimiento de regulaciones regionales (GDPR, etc.)
- ✅ Reduce carga del servidor filtrando tráfico no deseado

### Limitaciones
- ⚠️  No es 100% preciso (VPNs, proxies, Tor)
- ⚠️  IPs móviles pueden cambiar de país
- ⚠️  Usuarios legítimos con VPN pueden ser bloqueados
- ⚠️  Base de datos debe actualizarse regularmente (mensualmente)

### Mejores Prácticas

1. **No confiar solo en geolocalización**: Combinar con otros métodos de seguridad
2. **Actualizar base de datos**: Ejecutar script de descarga mensualmente
3. **Monitorear falsos positivos**: Revisar logs de bloqueos geo
4. **Modo whitelist para servicios críticos**: Más seguro que blacklist
5. **Permitir IPs conocidas**: Agregar IPs de confianza a whitelist IP

## Actualización de Base de Datos

La base de datos GeoLite2 se actualiza mensualmente. Para mantenerla actualizada:

```bash
# Configurar cron job (Linux)
# Ejecutar el 1º de cada mes a las 3 AM
0 3 1 * * /path/to/python /path/to/scripts/download_geoip_db.py

# O manualmente cada mes
python scripts/download_geoip_db.py
```

## Troubleshooting

### Error: "Base de datos GeoIP2 no encontrada"
```bash
# Verificar que existe el archivo
ls -lh data/GeoLite2-Country.mmdb

# Si no existe, descargar
python scripts/download_geoip_db.py TU_LICENSE_KEY
```

### Error: "License key inválida"
```bash
# Verificar que la key es correcta
# Regenerar key en: https://www.maxmind.com/en/accounts/current/license-key
```

### IPs privadas siendo bloqueadas
```python
# Las IPs privadas SIEMPRE son permitidas por defecto
# 127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16.x.x
# No requieren configuración especial
```

### País correcto pero bloqueado
```python
# Verificar configuración
config = db.get_geo_config()
print(f"Modo: {config['mode']}")
print(f"Países: {config['countries']}")

# Verificar país de IP
info = geo.get_country_info('IP_AQUI')
print(info)
```

## Soporte

Para más información o reportar problemas:
- Documentación GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
- Librería geoip2: https://github.com/maxmind/GeoIP2-python
