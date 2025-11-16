"""
Módulo de Geolocalización y Threat Intelligence
"""

import requests
import json
from datetime import datetime, timedelta


class GeoIntelligence:
    def __init__(self, db_manager):
        self.db = db_manager
        self.cache = {}  # Cache de lookups de IP
        self.cache_duration = 86400  # 24 horas

    def get_ip_info(self, ip_address):
        """Obtener información geográfica de una IP"""
        # Verificar cache
        if ip_address in self.cache:
            cached = self.cache[ip_address]
            if (datetime.utcnow() - cached['timestamp']).seconds < self.cache_duration:
                return cached['data']

        try:
            # Usar servicio gratuito ip-api.com
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    info = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone')
                    }

                    # Guardar en cache
                    self.cache[ip_address] = {
                        'timestamp': datetime.utcnow(),
                        'data': info
                    }

                    return info
        except Exception as e:
            print(f"Error getting IP info: {e}")

        return None

    def is_country_blocked(self, ip_address):
        """Verificar si el país de la IP está bloqueado"""
        geo_blocking_enabled = self.db.get_config('geo_blocking_enabled')
        if not geo_blocking_enabled:
            return False

        ip_info = self.get_ip_info(ip_address)
        if not ip_info:
            return False

        country_code = ip_info.get('country_code')
        if not country_code:
            return False

        blocked_countries = self.db.get_config('blocked_countries') or []

        return country_code in blocked_countries

    def check_threat_reputation(self, ip_address):
        """Verificar reputación de IP usando fuentes gratuitas y base de datos local"""
        try:
            # Analizar historial local (más importante)
            events = self.db.get_events_by_ip(ip_address, limit=100)

            high_severity_count = len([e for e in events if e.get('severity') in ['high', 'critical']])
            medium_severity_count = len([e for e in events if e.get('severity') == 'medium'])
            total_events = len(events)

            # Calcular score basado en eventos locales (0-100)
            local_score = 0
            if total_events > 0:
                local_score = min((high_severity_count * 10) + (medium_severity_count * 3), 70)

            # Verificar si fue bloqueada anteriormente
            was_blocked = len(self.db.get_blocked_ips(ip=ip_address)) > 0
            if was_blocked:
                local_score += 20

            # Determinar si es abusiva basado en score local
            is_abusive = local_score > 50

            # Obtener timestamp del último evento
            last_event_time = None
            if events:
                last_event_time = events[0].get('timestamp')

            return {
                'is_abusive': is_abusive,
                'abuse_score': min(local_score, 100),
                'total_reports': total_events,
                'last_reported': last_event_time,
                'is_whitelisted': self.db.is_ip_whitelisted(ip_address),
                'usage_type': 'local_analysis',
                'high_severity_events': high_severity_count,
                'medium_severity_events': medium_severity_count
            }
        except Exception as e:
            print(f"Error checking threat reputation: {e}")
            return {
                'is_abusive': False,
                'abuse_score': 0,
                'total_reports': 0,
                'last_reported': None,
                'is_whitelisted': False,
                'usage_type': 'error'
            }

    def is_known_vpn_proxy(self, ip_address):
        """Verificar si la IP es un VPN/Proxy conocido"""
        ip_info = self.get_ip_info(ip_address)
        if not ip_info:
            return False

        # Verificar ISP/ORG common de VPNs
        vpn_keywords = [
            'vpn', 'proxy', 'tor', 'relay', 'exit',
            'hosting', 'datacenter', 'cloud'
        ]

        isp = (ip_info.get('isp') or '').lower()
        org = (ip_info.get('org') or '').lower()

        for keyword in vpn_keywords:
            if keyword in isp or keyword in org:
                return True

        return False

    def is_cloud_provider(self, ip_address):
        """Verificar si la IP pertenece a un proveedor cloud"""
        ip_info = self.get_ip_info(ip_address)
        if not ip_info:
            return False

        cloud_providers = [
            'amazon', 'aws', 'microsoft', 'azure', 'google',
            'digitalocean', 'linode', 'ovh', 'hetzner',
            'vultr', 'rackspace', 'cloudflare'
        ]

        isp = (ip_info.get('isp') or '').lower()
        org = (ip_info.get('org') or '').lower()

        for provider in cloud_providers:
            if provider in isp or provider in org:
                return True

        return False

    def get_reputation_score(self, ip_address):
        """Obtener score de reputación de una IP (0-100, más alto = peor)"""
        score = 0

        # Verificar si está en blacklist local
        if self.db.is_ip_blacklisted(ip_address):
            return 100

        # Verificar reputación usando análisis local
        threat_data = self.check_threat_reputation(ip_address)
        if threat_data:
            score += threat_data.get('abuse_score', 0) * 0.6

        # Verificar historial de ataques en DB local
        events = self.db.get_events_by_ip(ip_address, limit=100)
        attack_count = len([e for e in events if e.get('severity') in ['high', 'critical']])
        score += min(attack_count * 5, 30)

        # Penalizar VPNs/Proxies
        if self.is_known_vpn_proxy(ip_address):
            score += 10

        # Penalizar ciertos países (si geo-blocking está habilitado)
        if self.is_country_blocked(ip_address):
            score += 20

        return min(score, 100)

    def enrich_ip_data(self, ip_address):
        """Enriquecer datos de una IP con toda la información disponible"""
        return {
            'ip_address': ip_address,
            'geo_info': self.get_ip_info(ip_address),
            'is_vpn_proxy': self.is_known_vpn_proxy(ip_address),
            'is_cloud': self.is_cloud_provider(ip_address),
            'is_blocked_country': self.is_country_blocked(ip_address),
            'threat_data': self.check_threat_reputation(ip_address),
            'reputation_score': self.get_reputation_score(ip_address),
            'attack_history': self.db.get_events_by_ip(ip_address, limit=10),
            'is_whitelisted': self.db.is_ip_whitelisted(ip_address),
            'is_blacklisted': self.db.is_ip_blacklisted(ip_address),
            'is_currently_blocked': self.db.is_ip_blocked(ip_address)
        }
