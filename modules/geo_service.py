"""
Servicio de Geolocalización IP
Permite identificar el país de origen de las IPs y filtrar acceso según configuración
"""
import os
import geoip2.database
import geoip2.errors
from typing import Optional, Dict, List
from datetime import datetime
import json


class GeoLocationService:
    """Servicio para geolocalización de IPs usando GeoLite2"""

    def __init__(self, db_manager, geoip_db_path='data/GeoLite2-Country.mmdb'):
        """
        Inicializar servicio de geolocalización

        Args:
            db_manager: Instancia de DatabaseManager
            geoip_db_path: Ruta a la base de datos GeoLite2
        """
        self.db = db_manager
        self.geoip_db_path = geoip_db_path
        self.reader = None

        # Intentar cargar la base de datos
        self._load_geoip_database()

    def _load_geoip_database(self):
        """Cargar la base de datos GeoIP2"""
        try:
            if os.path.exists(self.geoip_db_path):
                self.reader = geoip2.database.Reader(self.geoip_db_path)
                print(f"✅ Base de datos GeoIP2 cargada: {self.geoip_db_path}")
            else:
                print(f"⚠️  Base de datos GeoIP2 no encontrada: {self.geoip_db_path}")
                print("   Ejecuta 'python scripts/download_geoip_db.py' para descargarla")
        except Exception as e:
            print(f"❌ Error cargando base de datos GeoIP2: {e}")
            self.reader = None

    def get_country_info(self, ip_address: str) -> Optional[Dict]:
        """
        Obtener información del país para una IP

        Args:
            ip_address: Dirección IP a consultar

        Returns:
            Dict con información del país o None si no se encuentra
            {
                'country_code': 'US',
                'country_name': 'United States',
                'continent_code': 'NA',
                'continent_name': 'North America'
            }
        """
        if not self.reader:
            return None

        # IPs privadas o locales
        if self._is_private_ip(ip_address):
            return {
                'country_code': 'XX',
                'country_name': 'Private/Local Network',
                'continent_code': 'XX',
                'continent_name': 'Private'
            }

        try:
            response = self.reader.country(ip_address)
            return {
                'country_code': response.country.iso_code or 'XX',
                'country_name': response.country.name or 'Unknown',
                'continent_code': response.continent.code or 'XX',
                'continent_name': response.continent.name or 'Unknown'
            }
        except geoip2.errors.AddressNotFoundError:
            return {
                'country_code': 'XX',
                'country_name': 'Unknown',
                'continent_code': 'XX',
                'continent_name': 'Unknown'
            }
        except Exception as e:
            print(f"Error obteniendo información de país para {ip_address}: {e}")
            return None

    def _is_private_ip(self, ip_address: str) -> bool:
        """Verificar si una IP es privada o local"""
        private_ranges = [
            '127.',      # Localhost
            '10.',       # Private Class A
            '172.16.',   # Private Class B (simplified)
            '192.168.',  # Private Class C
            '::1',       # IPv6 localhost
            'fe80:',     # IPv6 link-local
            'fc00:',     # IPv6 unique local
        ]

        for prefix in private_ranges:
            if ip_address.startswith(prefix):
                return True

        return False

    def is_country_allowed(self, ip_address: str) -> tuple[bool, str]:
        """
        Verificar si el país de una IP está permitido según la configuración

        Args:
            ip_address: Dirección IP a verificar

        Returns:
            Tuple (permitido: bool, razón: str)
        """
        # Obtener configuración de países
        config = self.db.get_geo_config()

        if not config:
            # Si no hay configuración, permitir todo
            return True, "No hay restricciones geográficas configuradas"

        # Si el modo está desactivado, permitir todo
        if not config.get('enabled', False):
            return True, "Filtrado geográfico desactivado"

        # Obtener información del país
        country_info = self.get_country_info(ip_address)

        if not country_info:
            # Si no se puede determinar el país
            if config.get('block_unknown', False):
                return False, "País desconocido (bloqueado por configuración)"
            return True, "País desconocido (permitido por configuración)"

        country_code = country_info['country_code']
        country_name = country_info['country_name']

        # IPs privadas/locales siempre permitidas
        if country_code == 'XX' and 'Private' in country_name:
            return True, "IP privada/local"

        mode = config.get('mode', 'whitelist')  # whitelist o blacklist
        allowed_countries = config.get('countries', [])

        if mode == 'whitelist':
            # Solo permitir países en la lista
            if country_code in allowed_countries:
                return True, f"País permitido: {country_name} ({country_code})"
            else:
                return False, f"País no permitido: {country_name} ({country_code})"
        else:  # blacklist
            # Bloquear solo países en la lista
            if country_code in allowed_countries:
                return False, f"País bloqueado: {country_name} ({country_code})"
            else:
                return True, f"País permitido: {country_name} ({country_code})"

    def get_country_statistics(self, limit_days=30) -> List[Dict]:
        """
        Obtener estadísticas de acceso por país

        Args:
            limit_days: Días hacia atrás para analizar

        Returns:
            Lista de diccionarios con estadísticas por país
        """
        events = self.db.get_security_events(limit=10000)

        # Agrupar por país
        country_stats = {}

        for event in events:
            ip = event.get('source_ip')
            if not ip:
                continue

            country_info = self.get_country_info(ip)
            if not country_info:
                continue

            country_code = country_info['country_code']
            country_name = country_info['country_name']

            if country_code not in country_stats:
                country_stats[country_code] = {
                    'country_code': country_code,
                    'country_name': country_name,
                    'total_events': 0,
                    'unique_ips': set(),
                    'malicious_events': 0,
                    'event_types': {}
                }

            stats = country_stats[country_code]
            stats['total_events'] += 1
            stats['unique_ips'].add(ip)

            # Contar eventos maliciosos
            severity = event.get('severity', 'low')
            if severity in ['critical', 'high']:
                stats['malicious_events'] += 1

            # Contar tipos de eventos
            event_type = event.get('event_type', 'unknown')
            stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1

        # Convertir a lista y agregar estadísticas calculadas
        result = []
        for code, stats in country_stats.items():
            stats['unique_ips'] = len(stats['unique_ips'])
            stats['malicious_percentage'] = (
                stats['malicious_events'] / stats['total_events'] * 100
                if stats['total_events'] > 0 else 0
            )
            result.append(stats)

        # Ordenar por total de eventos (descendente)
        result.sort(key=lambda x: x['total_events'], reverse=True)

        return result

    def enrich_event_with_geo(self, event_data: Dict) -> Dict:
        """
        Enriquecer un evento con información geográfica

        Args:
            event_data: Diccionario con datos del evento

        Returns:
            Evento enriquecido con información geo
        """
        ip = event_data.get('source_ip')
        if not ip:
            return event_data

        country_info = self.get_country_info(ip)
        if country_info:
            event_data['country_code'] = country_info['country_code']
            event_data['country_name'] = country_info['country_name']
            event_data['continent_code'] = country_info['continent_code']

        return event_data

    def __del__(self):
        """Cerrar la base de datos GeoIP al destruir el objeto"""
        if self.reader:
            try:
                self.reader.close()
            except:
                pass


# Lista de países comunes para la UI
COMMON_COUNTRIES = [
    {'code': 'AR', 'name': 'Argentina'},
    {'code': 'BR', 'name': 'Brasil'},
    {'code': 'CL', 'name': 'Chile'},
    {'code': 'CO', 'name': 'Colombia'},
    {'code': 'MX', 'name': 'México'},
    {'code': 'PE', 'name': 'Perú'},
    {'code': 'UY', 'name': 'Uruguay'},
    {'code': 'VE', 'name': 'Venezuela'},
    {'code': 'ES', 'name': 'España'},
    {'code': 'US', 'name': 'Estados Unidos'},
    {'code': 'CA', 'name': 'Canadá'},
    {'code': 'GB', 'name': 'Reino Unido'},
    {'code': 'DE', 'name': 'Alemania'},
    {'code': 'FR', 'name': 'Francia'},
    {'code': 'IT', 'name': 'Italia'},
    {'code': 'CN', 'name': 'China'},
    {'code': 'JP', 'name': 'Japón'},
    {'code': 'KR', 'name': 'Corea del Sur'},
    {'code': 'IN', 'name': 'India'},
    {'code': 'RU', 'name': 'Rusia'},
]


def get_all_countries() -> List[Dict]:
    """
    Obtener lista completa de países ISO 3166-1 alpha-2

    Returns:
        Lista de diccionarios con código y nombre de país
    """
    # Lista completa de códigos ISO de países
    # Fuente: ISO 3166-1 alpha-2
    countries = [
        {'code': 'AD', 'name': 'Andorra'},
        {'code': 'AE', 'name': 'Emiratos Árabes Unidos'},
        {'code': 'AF', 'name': 'Afganistán'},
        {'code': 'AG', 'name': 'Antigua y Barbuda'},
        {'code': 'AI', 'name': 'Anguila'},
        {'code': 'AL', 'name': 'Albania'},
        {'code': 'AM', 'name': 'Armenia'},
        {'code': 'AO', 'name': 'Angola'},
        {'code': 'AQ', 'name': 'Antártida'},
        {'code': 'AR', 'name': 'Argentina'},
        {'code': 'AS', 'name': 'Samoa Americana'},
        {'code': 'AT', 'name': 'Austria'},
        {'code': 'AU', 'name': 'Australia'},
        {'code': 'AW', 'name': 'Aruba'},
        {'code': 'AX', 'name': 'Islas Åland'},
        {'code': 'AZ', 'name': 'Azerbaiyán'},
        {'code': 'BA', 'name': 'Bosnia y Herzegovina'},
        {'code': 'BB', 'name': 'Barbados'},
        {'code': 'BD', 'name': 'Bangladés'},
        {'code': 'BE', 'name': 'Bélgica'},
        {'code': 'BF', 'name': 'Burkina Faso'},
        {'code': 'BG', 'name': 'Bulgaria'},
        {'code': 'BH', 'name': 'Baréin'},
        {'code': 'BI', 'name': 'Burundi'},
        {'code': 'BJ', 'name': 'Benín'},
        {'code': 'BL', 'name': 'San Bartolomé'},
        {'code': 'BM', 'name': 'Bermudas'},
        {'code': 'BN', 'name': 'Brunéi'},
        {'code': 'BO', 'name': 'Bolivia'},
        {'code': 'BQ', 'name': 'Bonaire, San Eustaquio y Saba'},
        {'code': 'BR', 'name': 'Brasil'},
        {'code': 'BS', 'name': 'Bahamas'},
        {'code': 'BT', 'name': 'Bután'},
        {'code': 'BV', 'name': 'Isla Bouvet'},
        {'code': 'BW', 'name': 'Botsuana'},
        {'code': 'BY', 'name': 'Bielorrusia'},
        {'code': 'BZ', 'name': 'Belice'},
        {'code': 'CA', 'name': 'Canadá'},
        {'code': 'CC', 'name': 'Islas Cocos'},
        {'code': 'CD', 'name': 'República Democrática del Congo'},
        {'code': 'CF', 'name': 'República Centroafricana'},
        {'code': 'CG', 'name': 'Congo'},
        {'code': 'CH', 'name': 'Suiza'},
        {'code': 'CI', 'name': 'Costa de Marfil'},
        {'code': 'CK', 'name': 'Islas Cook'},
        {'code': 'CL', 'name': 'Chile'},
        {'code': 'CM', 'name': 'Camerún'},
        {'code': 'CN', 'name': 'China'},
        {'code': 'CO', 'name': 'Colombia'},
        {'code': 'CR', 'name': 'Costa Rica'},
        {'code': 'CU', 'name': 'Cuba'},
        {'code': 'CV', 'name': 'Cabo Verde'},
        {'code': 'CW', 'name': 'Curazao'},
        {'code': 'CX', 'name': 'Isla de Navidad'},
        {'code': 'CY', 'name': 'Chipre'},
        {'code': 'CZ', 'name': 'República Checa'},
        {'code': 'DE', 'name': 'Alemania'},
        {'code': 'DJ', 'name': 'Yibuti'},
        {'code': 'DK', 'name': 'Dinamarca'},
        {'code': 'DM', 'name': 'Dominica'},
        {'code': 'DO', 'name': 'República Dominicana'},
        {'code': 'DZ', 'name': 'Argelia'},
        {'code': 'EC', 'name': 'Ecuador'},
        {'code': 'EE', 'name': 'Estonia'},
        {'code': 'EG', 'name': 'Egipto'},
        {'code': 'EH', 'name': 'Sáhara Occidental'},
        {'code': 'ER', 'name': 'Eritrea'},
        {'code': 'ES', 'name': 'España'},
        {'code': 'ET', 'name': 'Etiopía'},
        {'code': 'FI', 'name': 'Finlandia'},
        {'code': 'FJ', 'name': 'Fiyi'},
        {'code': 'FK', 'name': 'Islas Malvinas'},
        {'code': 'FM', 'name': 'Micronesia'},
        {'code': 'FO', 'name': 'Islas Feroe'},
        {'code': 'FR', 'name': 'Francia'},
        {'code': 'GA', 'name': 'Gabón'},
        {'code': 'GB', 'name': 'Reino Unido'},
        {'code': 'GD', 'name': 'Granada'},
        {'code': 'GE', 'name': 'Georgia'},
        {'code': 'GF', 'name': 'Guayana Francesa'},
        {'code': 'GG', 'name': 'Guernsey'},
        {'code': 'GH', 'name': 'Ghana'},
        {'code': 'GI', 'name': 'Gibraltar'},
        {'code': 'GL', 'name': 'Groenlandia'},
        {'code': 'GM', 'name': 'Gambia'},
        {'code': 'GN', 'name': 'Guinea'},
        {'code': 'GP', 'name': 'Guadalupe'},
        {'code': 'GQ', 'name': 'Guinea Ecuatorial'},
        {'code': 'GR', 'name': 'Grecia'},
        {'code': 'GS', 'name': 'Georgia del Sur e Islas Sandwich del Sur'},
        {'code': 'GT', 'name': 'Guatemala'},
        {'code': 'GU', 'name': 'Guam'},
        {'code': 'GW', 'name': 'Guinea-Bisáu'},
        {'code': 'GY', 'name': 'Guyana'},
        {'code': 'HK', 'name': 'Hong Kong'},
        {'code': 'HM', 'name': 'Islas Heard y McDonald'},
        {'code': 'HN', 'name': 'Honduras'},
        {'code': 'HR', 'name': 'Croacia'},
        {'code': 'HT', 'name': 'Haití'},
        {'code': 'HU', 'name': 'Hungría'},
        {'code': 'ID', 'name': 'Indonesia'},
        {'code': 'IE', 'name': 'Irlanda'},
        {'code': 'IL', 'name': 'Israel'},
        {'code': 'IM', 'name': 'Isla de Man'},
        {'code': 'IN', 'name': 'India'},
        {'code': 'IO', 'name': 'Territorio Británico del Océano Índico'},
        {'code': 'IQ', 'name': 'Irak'},
        {'code': 'IR', 'name': 'Irán'},
        {'code': 'IS', 'name': 'Islandia'},
        {'code': 'IT', 'name': 'Italia'},
        {'code': 'JE', 'name': 'Jersey'},
        {'code': 'JM', 'name': 'Jamaica'},
        {'code': 'JO', 'name': 'Jordania'},
        {'code': 'JP', 'name': 'Japón'},
        {'code': 'KE', 'name': 'Kenia'},
        {'code': 'KG', 'name': 'Kirguistán'},
        {'code': 'KH', 'name': 'Camboya'},
        {'code': 'KI', 'name': 'Kiribati'},
        {'code': 'KM', 'name': 'Comoras'},
        {'code': 'KN', 'name': 'San Cristóbal y Nieves'},
        {'code': 'KP', 'name': 'Corea del Norte'},
        {'code': 'KR', 'name': 'Corea del Sur'},
        {'code': 'KW', 'name': 'Kuwait'},
        {'code': 'KY', 'name': 'Islas Caimán'},
        {'code': 'KZ', 'name': 'Kazajistán'},
        {'code': 'LA', 'name': 'Laos'},
        {'code': 'LB', 'name': 'Líbano'},
        {'code': 'LC', 'name': 'Santa Lucía'},
        {'code': 'LI', 'name': 'Liechtenstein'},
        {'code': 'LK', 'name': 'Sri Lanka'},
        {'code': 'LR', 'name': 'Liberia'},
        {'code': 'LS', 'name': 'Lesoto'},
        {'code': 'LT', 'name': 'Lituania'},
        {'code': 'LU', 'name': 'Luxemburgo'},
        {'code': 'LV', 'name': 'Letonia'},
        {'code': 'LY', 'name': 'Libia'},
        {'code': 'MA', 'name': 'Marruecos'},
        {'code': 'MC', 'name': 'Mónaco'},
        {'code': 'MD', 'name': 'Moldavia'},
        {'code': 'ME', 'name': 'Montenegro'},
        {'code': 'MF', 'name': 'San Martín'},
        {'code': 'MG', 'name': 'Madagascar'},
        {'code': 'MH', 'name': 'Islas Marshall'},
        {'code': 'MK', 'name': 'Macedonia del Norte'},
        {'code': 'ML', 'name': 'Malí'},
        {'code': 'MM', 'name': 'Myanmar'},
        {'code': 'MN', 'name': 'Mongolia'},
        {'code': 'MO', 'name': 'Macao'},
        {'code': 'MP', 'name': 'Islas Marianas del Norte'},
        {'code': 'MQ', 'name': 'Martinica'},
        {'code': 'MR', 'name': 'Mauritania'},
        {'code': 'MS', 'name': 'Montserrat'},
        {'code': 'MT', 'name': 'Malta'},
        {'code': 'MU', 'name': 'Mauricio'},
        {'code': 'MV', 'name': 'Maldivas'},
        {'code': 'MW', 'name': 'Malaui'},
        {'code': 'MX', 'name': 'México'},
        {'code': 'MY', 'name': 'Malasia'},
        {'code': 'MZ', 'name': 'Mozambique'},
        {'code': 'NA', 'name': 'Namibia'},
        {'code': 'NC', 'name': 'Nueva Caledonia'},
        {'code': 'NE', 'name': 'Níger'},
        {'code': 'NF', 'name': 'Isla Norfolk'},
        {'code': 'NG', 'name': 'Nigeria'},
        {'code': 'NI', 'name': 'Nicaragua'},
        {'code': 'NL', 'name': 'Países Bajos'},
        {'code': 'NO', 'name': 'Noruega'},
        {'code': 'NP', 'name': 'Nepal'},
        {'code': 'NR', 'name': 'Nauru'},
        {'code': 'NU', 'name': 'Niue'},
        {'code': 'NZ', 'name': 'Nueva Zelanda'},
        {'code': 'OM', 'name': 'Omán'},
        {'code': 'PA', 'name': 'Panamá'},
        {'code': 'PE', 'name': 'Perú'},
        {'code': 'PF', 'name': 'Polinesia Francesa'},
        {'code': 'PG', 'name': 'Papúa Nueva Guinea'},
        {'code': 'PH', 'name': 'Filipinas'},
        {'code': 'PK', 'name': 'Pakistán'},
        {'code': 'PL', 'name': 'Polonia'},
        {'code': 'PM', 'name': 'San Pedro y Miquelón'},
        {'code': 'PN', 'name': 'Islas Pitcairn'},
        {'code': 'PR', 'name': 'Puerto Rico'},
        {'code': 'PS', 'name': 'Palestina'},
        {'code': 'PT', 'name': 'Portugal'},
        {'code': 'PW', 'name': 'Palaos'},
        {'code': 'PY', 'name': 'Paraguay'},
        {'code': 'QA', 'name': 'Catar'},
        {'code': 'RE', 'name': 'Reunión'},
        {'code': 'RO', 'name': 'Rumania'},
        {'code': 'RS', 'name': 'Serbia'},
        {'code': 'RU', 'name': 'Rusia'},
        {'code': 'RW', 'name': 'Ruanda'},
        {'code': 'SA', 'name': 'Arabia Saudita'},
        {'code': 'SB', 'name': 'Islas Salomón'},
        {'code': 'SC', 'name': 'Seychelles'},
        {'code': 'SD', 'name': 'Sudán'},
        {'code': 'SE', 'name': 'Suecia'},
        {'code': 'SG', 'name': 'Singapur'},
        {'code': 'SH', 'name': 'Santa Elena, Ascensión y Tristán de Acuña'},
        {'code': 'SI', 'name': 'Eslovenia'},
        {'code': 'SJ', 'name': 'Svalbard y Jan Mayen'},
        {'code': 'SK', 'name': 'Eslovaquia'},
        {'code': 'SL', 'name': 'Sierra Leona'},
        {'code': 'SM', 'name': 'San Marino'},
        {'code': 'SN', 'name': 'Senegal'},
        {'code': 'SO', 'name': 'Somalia'},
        {'code': 'SR', 'name': 'Surinam'},
        {'code': 'SS', 'name': 'Sudán del Sur'},
        {'code': 'ST', 'name': 'Santo Tomé y Príncipe'},
        {'code': 'SV', 'name': 'El Salvador'},
        {'code': 'SX', 'name': 'Sint Maarten'},
        {'code': 'SY', 'name': 'Siria'},
        {'code': 'SZ', 'name': 'Esuatini'},
        {'code': 'TC', 'name': 'Islas Turcas y Caicos'},
        {'code': 'TD', 'name': 'Chad'},
        {'code': 'TF', 'name': 'Territorios Australes Franceses'},
        {'code': 'TG', 'name': 'Togo'},
        {'code': 'TH', 'name': 'Tailandia'},
        {'code': 'TJ', 'name': 'Tayikistán'},
        {'code': 'TK', 'name': 'Tokelau'},
        {'code': 'TL', 'name': 'Timor Oriental'},
        {'code': 'TM', 'name': 'Turkmenistán'},
        {'code': 'TN', 'name': 'Túnez'},
        {'code': 'TO', 'name': 'Tonga'},
        {'code': 'TR', 'name': 'Turquía'},
        {'code': 'TT', 'name': 'Trinidad y Tobago'},
        {'code': 'TV', 'name': 'Tuvalu'},
        {'code': 'TW', 'name': 'Taiwán'},
        {'code': 'TZ', 'name': 'Tanzania'},
        {'code': 'UA', 'name': 'Ucrania'},
        {'code': 'UG', 'name': 'Uganda'},
        {'code': 'UM', 'name': 'Islas Ultramarinas Menores de los Estados Unidos'},
        {'code': 'US', 'name': 'Estados Unidos'},
        {'code': 'UY', 'name': 'Uruguay'},
        {'code': 'UZ', 'name': 'Uzbekistán'},
        {'code': 'VA', 'name': 'Ciudad del Vaticano'},
        {'code': 'VC', 'name': 'San Vicente y las Granadinas'},
        {'code': 'VE', 'name': 'Venezuela'},
        {'code': 'VG', 'name': 'Islas Vírgenes Británicas'},
        {'code': 'VI', 'name': 'Islas Vírgenes de los Estados Unidos'},
        {'code': 'VN', 'name': 'Vietnam'},
        {'code': 'VU', 'name': 'Vanuatu'},
        {'code': 'WF', 'name': 'Wallis y Futuna'},
        {'code': 'WS', 'name': 'Samoa'},
        {'code': 'YE', 'name': 'Yemen'},
        {'code': 'YT', 'name': 'Mayotte'},
        {'code': 'ZA', 'name': 'Sudáfrica'},
        {'code': 'ZM', 'name': 'Zambia'},
        {'code': 'ZW', 'name': 'Zimbabue'},
    ]

    return sorted(countries, key=lambda x: x['name'])
