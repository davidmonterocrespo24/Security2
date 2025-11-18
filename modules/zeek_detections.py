"""
Módulo de detecciones avanzadas con Zeek
Port scans, DNS tunneling, análisis SSL/TLS, detección de malware
"""

import math
from datetime import datetime, timedelta
from collections import Counter, defaultdict


class ZeekDetections:
    """Detecciones avanzadas basadas en datos de Zeek"""

    def __init__(self, db_manager):
        self.db = db_manager

    def detect_port_scan_from_conn_log(self, hours_back=1, min_ports=15, max_time_window=60):
        """
        Detectar escaneos de puertos usando análisis avanzado

        Args:
            hours_back: Horas hacia atrás a analizar
            min_ports: Mínimo de puertos para considerar scan
            max_time_window: Ventana de tiempo máxima en segundos

        Returns:
            list: [{
                'ip': str,
                'ports_scanned': int,
                'time_window': float,
                'scan_rate': float,  # puertos/segundo
                'severity': str,
                'ports': list
            }]
        """
        from database.models import ZeekConnection

        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            # Obtener conexiones
            conns = session.query(ZeekConnection).filter(
                ZeekConnection.timestamp >= cutoff
            ).order_by(ZeekConnection.timestamp).all()

            # Agrupar por IP origen
            ip_data = defaultdict(lambda: {
                'ports': set(),
                'timestamps': [],
                'dest_ips': set()
            })

            for conn in conns:
                if not conn.source_ip or not conn.dest_port:
                    continue

                ip_data[conn.source_ip]['ports'].add(conn.dest_port)
                ip_data[conn.source_ip]['timestamps'].append(conn.timestamp)
                if conn.dest_ip:
                    ip_data[conn.source_ip]['dest_ips'].add(conn.dest_ip)

            # Analizar cada IP
            port_scanners = []

            for ip, data in ip_data.items():
                ports = data['ports']
                timestamps = sorted(data['timestamps'])

                if len(ports) < min_ports:
                    continue

                # Calcular ventana de tiempo
                if len(timestamps) >= 2:
                    time_window = (timestamps[-1] - timestamps[0]).total_seconds()
                else:
                    time_window = 0

                # Calcular scan rate
                scan_rate = len(ports) / max(time_window, 1)

                # Determinar severidad
                if len(ports) >= 100 or scan_rate >= 10:
                    severity = 'critical'
                elif len(ports) >= 50 or scan_rate >= 5:
                    severity = 'high'
                elif len(ports) >= 25:
                    severity = 'medium'
                else:
                    severity = 'low'

                port_scanners.append({
                    'ip': ip,
                    'ports_scanned': len(ports),
                    'unique_destinations': len(data['dest_ips']),
                    'time_window': round(time_window, 2),
                    'scan_rate': round(scan_rate, 2),
                    'severity': severity,
                    'ports': sorted(list(ports))[:50],  # Top 50
                    'first_seen': timestamps[0].isoformat() if timestamps else None,
                    'last_seen': timestamps[-1].isoformat() if timestamps else None
                })

            # Ordenar por severidad y cantidad
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            port_scanners.sort(key=lambda x: (severity_order[x['severity']], -x['ports_scanned']))

            # Crear alertas automáticas para casos críticos
            for scanner in port_scanners[:5]:  # Top 5
                if scanner['severity'] in ['critical', 'high']:
                    self._create_threat_alert(
                        ip=scanner['ip'],
                        threat_type='port_scan',
                        severity=scanner['severity'],
                        description=f"Port scan detectado: {scanner['ports_scanned']} puertos en {scanner['time_window']}s ({scanner['scan_rate']} p/s)"
                    )

            return port_scanners

        finally:
            session.close()

    def analyze_dns_queries(self, hours_back=24):
        """
        Análisis completo de queries DNS

        Returns:
            dict: {
                'dga_detected': list,  # Domain Generation Algorithm
                'tunneling_detected': list,
                'high_volume_ips': list,
                'suspicious_domains': list
            }
        """
        from database.models import ZeekDNS

        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            queries = session.query(ZeekDNS).filter(
                ZeekDNS.timestamp >= cutoff
            ).all()

            dga_domains = []
            tunneling_suspects = []
            ip_query_count = defaultdict(int)
            domain_counter = Counter()

            for query in queries:
                query_str = query.query or ''
                source_ip = query.source_ip

                # 1. DGA Detection (alta entropía)
                entropy = self._calculate_entropy(query_str)
                if entropy >= 3.8:
                    # Verificar que no sea dominio legítimo conocido
                    if not self._is_known_domain(query_str):
                        dga_domains.append({
                            'domain': query_str,
                            'entropy': entropy,
                            'source_ip': source_ip,
                            'timestamp': query.timestamp.isoformat() if query.timestamp else None
                        })

                        # Actualizar flag en BD
                        query.is_suspicious = True

                # 2. DNS Tunneling (queries muy largas + subdominios)
                subdomain_count = query_str.count('.')
                if len(query_str) > 60 and subdomain_count >= 3:
                    tunneling_suspects.append({
                        'domain': query_str,
                        'length': len(query_str),
                        'subdomain_levels': subdomain_count,
                        'source_ip': source_ip,
                        'entropy': entropy
                    })

                    query.is_tunneling = True

                # 3. Volumen de queries por IP
                ip_query_count[source_ip] += 1

                # 4. Contar dominios populares
                domain_counter[query_str] += 1

            # IPs con alto volumen de queries
            high_volume_ips = [
                {'ip': ip, 'query_count': count}
                for ip, count in ip_query_count.items()
                if count >= 100
            ]
            high_volume_ips.sort(key=lambda x: x['query_count'], reverse=True)

            # Dominios sospechosos (muchas queries a dominios raros)
            suspicious_domains = []
            for domain, count in domain_counter.most_common(50):
                entropy = self._calculate_entropy(domain)
                if entropy >= 3.5 and count >= 10:
                    suspicious_domains.append({
                        'domain': domain,
                        'query_count': count,
                        'entropy': entropy
                    })

            session.commit()

            # Crear alertas para casos críticos
            for dga in dga_domains[:10]:
                if dga['entropy'] >= 4.5:
                    self._create_threat_alert(
                        ip=dga['source_ip'],
                        threat_type='dns_dga',
                        severity='high',
                        description=f"Posible DGA detectado: {dga['domain']} (entropía: {dga['entropy']})"
                    )

            for tunnel in tunneling_suspects[:5]:
                self._create_threat_alert(
                    ip=tunnel['source_ip'],
                    threat_type='dns_tunneling',
                    severity='critical',
                    description=f"Posible DNS tunneling: {tunnel['domain']} ({tunnel['length']} chars)"
                )

            return {
                'dga_detected': dga_domains[:50],
                'tunneling_detected': tunneling_suspects[:50],
                'high_volume_ips': high_volume_ips[:20],
                'suspicious_domains': suspicious_domains
            }

        finally:
            session.close()

    def analyze_ssl_connections(self, hours_back=24):
        """
        Analizar conexiones SSL/TLS

        Returns:
            dict: {
                'self_signed_certs': list,
                'expired_certs': list,
                'weak_ciphers': list,
                'suspicious_issuers': list
            }
        """
        from database.models import ZeekSSL

        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            ssl_conns = session.query(ZeekSSL).filter(
                ZeekSSL.timestamp >= cutoff
            ).all()

            self_signed = []
            expired = []
            weak_ciphers = []
            issuer_counter = Counter()

            for ssl in ssl_conns:
                # 1. Certificados auto-firmados
                if ssl.is_self_signed:
                    self_signed.append({
                        'source_ip': ssl.source_ip,
                        'dest_ip': ssl.dest_ip,
                        'server_name': ssl.server_name,
                        'subject': ssl.subject,
                        'timestamp': ssl.timestamp.isoformat() if ssl.timestamp else None
                    })

                # 2. Certificados expirados
                if ssl.is_expired:
                    expired.append({
                        'source_ip': ssl.source_ip,
                        'dest_ip': ssl.dest_ip,
                        'server_name': ssl.server_name,
                        'not_valid_after': ssl.not_valid_after.isoformat() if ssl.not_valid_after else None
                    })

                # 3. Ciphers débiles
                if ssl.is_weak_cipher:
                    weak_ciphers.append({
                        'source_ip': ssl.source_ip,
                        'dest_ip': ssl.dest_ip,
                        'server_name': ssl.server_name,
                        'version': ssl.version,
                        'cipher': ssl.cipher
                    })

                # 4. Contar issuers
                if ssl.issuer:
                    issuer_counter[ssl.issuer] += 1

            # Issuers sospechosos (poco comunes)
            common_issuers = {'Let\'s Encrypt', 'DigiCert', 'GeoTrust', 'Comodo', 'Cloudflare'}
            suspicious_issuers = []

            for issuer, count in issuer_counter.items():
                if count >= 5 and not any(common in issuer for common in common_issuers):
                    suspicious_issuers.append({
                        'issuer': issuer,
                        'connection_count': count
                    })

            # Crear alertas
            for cert in self_signed[:10]:
                self._create_threat_alert(
                    ip=cert['source_ip'],
                    threat_type='ssl_self_signed',
                    severity='medium',
                    description=f"Certificado auto-firmado detectado: {cert['server_name']}"
                )

            return {
                'self_signed_certs': self_signed[:50],
                'expired_certs': expired[:50],
                'weak_ciphers': weak_ciphers[:50],
                'suspicious_issuers': suspicious_issuers
            }

        finally:
            session.close()

    def detect_beaconing(self, hours_back=24, regularity_threshold=0.9):
        """
        Detectar beaconing (comunicación periódica con C&C)

        Args:
            hours_back: Horas a analizar
            regularity_threshold: Umbral de regularidad (0-1)

        Returns:
            list: IPs con posible beaconing
        """
        from database.models import ZeekConnection

        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            conns = session.query(ZeekConnection).filter(
                ZeekConnection.timestamp >= cutoff
            ).order_by(ZeekConnection.timestamp).all()

            # Agrupar conexiones por (source_ip, dest_ip, dest_port)
            flows = defaultdict(list)

            for conn in conns:
                key = (conn.source_ip, conn.dest_ip, conn.dest_port)
                flows[key].append(conn.timestamp)

            beaconing_suspects = []

            for (src_ip, dst_ip, dst_port), timestamps in flows.items():
                if len(timestamps) < 10:  # Mínimo 10 conexiones
                    continue

                # Calcular intervalos entre conexiones
                timestamps = sorted(timestamps)
                intervals = []

                for i in range(1, len(timestamps)):
                    interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                    intervals.append(interval)

                # Calcular regularidad (desviación estándar baja = regular)
                if intervals:
                    mean_interval = sum(intervals) / len(intervals)
                    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                    std_dev = math.sqrt(variance)

                    # Coeficiente de variación (CV)
                    cv = std_dev / mean_interval if mean_interval > 0 else 0

                    # CV bajo = alta regularidad
                    regularity = 1 - min(cv, 1.0)

                    if regularity >= regularity_threshold:
                        beaconing_suspects.append({
                            'source_ip': src_ip,
                            'dest_ip': dst_ip,
                            'dest_port': dst_port,
                            'connection_count': len(timestamps),
                            'mean_interval': round(mean_interval, 2),
                            'regularity': round(regularity, 3),
                            'first_seen': timestamps[0].isoformat(),
                            'last_seen': timestamps[-1].isoformat()
                        })

            # Ordenar por regularidad
            beaconing_suspects.sort(key=lambda x: x['regularity'], reverse=True)

            # Crear alertas
            for beacon in beaconing_suspects[:5]:
                self._create_threat_alert(
                    ip=beacon['source_ip'],
                    threat_type='beaconing',
                    severity='critical',
                    description=f"Posible beaconing a {beacon['dest_ip']}:{beacon['dest_port']} (regularidad: {beacon['regularity']*100:.0f}%)"
                )

            return beaconing_suspects

        finally:
            session.close()

    def _calculate_entropy(self, string):
        """Calcular entropía de Shannon"""
        if not string:
            return 0.0

        char_freq = Counter(string)
        string_len = len(string)

        entropy = 0.0
        for count in char_freq.values():
            probability = count / string_len
            entropy -= probability * math.log2(probability)

        return round(entropy, 2)

    def _is_known_domain(self, domain):
        """Verificar si es un dominio conocido/legítimo"""
        known_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'twitter.com', 'linkedin.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
            'cloudflare.com', 'akamai.com', 'googleapis.com', 'gstatic.com',
            'azure.com', 'amazonaws.com'
        ]

        domain_lower = domain.lower()

        for known in known_domains:
            if known in domain_lower:
                return True

        return False

    def _create_threat_alert(self, ip, threat_type, severity, description):
        """Crear alerta de amenaza en la base de datos"""
        from database.models import Threat, Alert

        session = self.db.get_session()

        try:
            # Crear Threat
            threat = Threat(
                detected_at=datetime.utcnow(),
                threat_type=threat_type,
                severity=severity,
                source=ip,
                description=description,
                evidence=None,
                is_resolved=False
            )
            session.add(threat)

            # Crear Alert
            alert = Alert(
                created_at=datetime.utcnow(),
                alert_type=threat_type,
                severity=severity,
                title=f"{threat_type.upper()} detectado",
                message=description,
                source='zeek',
                is_read=False,
                is_resolved=False
            )
            session.add(alert)

            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error creando alerta: {e}")
        finally:
            session.close()
