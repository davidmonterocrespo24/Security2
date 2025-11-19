"""
Integración de Zeek con Machine Learning
Extrae características de Zeek para enriquecer el modelo ML y crea eventos automáticos
"""

from datetime import datetime, timedelta
from database.models import ZeekConnection, ZeekDNS, ZeekHTTP, ZeekSSL, SecurityEvent
from sqlalchemy import func, distinct


class ZeekMLIntegration:
    """Integración entre Zeek y Machine Learning"""

    def __init__(self, db_manager):
        self.db = db_manager

        # Inicializar sistema de alertas
        self.alert_manager = None
        try:
            from modules.alert_manager import AlertManager
            self.alert_manager = AlertManager(db_manager)
        except Exception as e:
            print(f"Advertencia: No se pudo inicializar AlertManager: {e}")

    def extract_zeek_features_for_ip(self, ip_address, hours_back=24):
        """
        Extraer características de Zeek para una IP específica

        Args:
            ip_address: IP a analizar
            hours_back: Horas hacia atrás para buscar

        Returns:
            dict: Diccionario con 18 características de Zeek
        """
        session = self.db.get_session()
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)

        features = {
            # Conexiones
            'zeek_connections_count': 0,
            'zeek_unique_dest_ports': 0,
            'zeek_unique_dest_ips': 0,
            'zeek_bytes_sent': 0,
            'zeek_bytes_received': 0,
            'zeek_packets_sent': 0,
            'zeek_packets_received': 0,
            'zeek_avg_duration': 0.0,
            'zeek_failed_connections': 0,

            # DNS
            'zeek_dns_queries': 0,
            'zeek_unique_domains': 0,
            'zeek_failed_dns': 0,

            # HTTP
            'zeek_http_requests': 0,
            'zeek_http_methods_diversity': 0,
            'zeek_suspicious_user_agents': 0,

            # SSL
            'zeek_ssl_connections': 0,
            'zeek_ssl_invalid_certs': 0,

            # Patrones
            'zeek_connection_regularity': 0.0  # Para detectar beaconing
        }

        try:
            # === CONEXIONES ===
            connections = session.query(ZeekConnection).filter(
                ZeekConnection.source_ip == ip_address,
                ZeekConnection.timestamp >= cutoff_time
            ).all()

            if connections:
                features['zeek_connections_count'] = len(connections)

                # Puertos únicos (port scanning)
                dest_ports = set(c.dest_port for c in connections if c.dest_port)
                features['zeek_unique_dest_ports'] = len(dest_ports)

                # IPs de destino únicas
                dest_ips = set(c.dest_ip for c in connections if c.dest_ip)
                features['zeek_unique_dest_ips'] = len(dest_ips)

                # Bytes y paquetes
                features['zeek_bytes_sent'] = sum(c.orig_bytes or 0 for c in connections)
                features['zeek_bytes_received'] = sum(c.resp_bytes or 0 for c in connections)
                features['zeek_packets_sent'] = sum(c.orig_pkts or 0 for c in connections)
                features['zeek_packets_received'] = sum(c.resp_pkts or 0 for c in connections)

                # Duración promedio
                durations = [c.duration for c in connections if c.duration]
                if durations:
                    features['zeek_avg_duration'] = sum(durations) / len(durations)

                # Conexiones fallidas (conn_state indica fallo)
                failed_states = ['S0', 'REJ', 'RSTO', 'RSTOS0']
                features['zeek_failed_connections'] = sum(
                    1 for c in connections if c.conn_state in failed_states
                )

                # Calcular regularidad (beaconing detection)
                if len(connections) > 5:
                    timestamps = sorted([c.timestamp for c in connections if c.timestamp])
                    if len(timestamps) > 1:
                        intervals = [
                            (timestamps[i+1] - timestamps[i]).total_seconds()
                            for i in range(len(timestamps) - 1)
                        ]
                        if intervals:
                            import statistics
                            mean_interval = statistics.mean(intervals)
                            if mean_interval > 0:
                                std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
                                # Coeficiente de variación (CV)
                                cv = std_interval / mean_interval
                                # Regularidad = 1 - CV (más cercano a 1 = más regular)
                                features['zeek_connection_regularity'] = max(0, 1 - cv)

            # === DNS ===
            dns_queries = session.query(ZeekDNS).filter(
                ZeekDNS.source_ip == ip_address,
                ZeekDNS.timestamp >= cutoff_time
            ).all()

            if dns_queries:
                features['zeek_dns_queries'] = len(dns_queries)

                # Dominios únicos
                domains = set(d.query for d in dns_queries if d.query)
                features['zeek_unique_domains'] = len(domains)

                # DNS fallidos
                features['zeek_failed_dns'] = sum(
                    1 for d in dns_queries if d.rcode and d.rcode != 0
                )

            # === HTTP ===
            http_requests = session.query(ZeekHTTP).filter(
                ZeekHTTP.source_ip == ip_address,
                ZeekHTTP.timestamp >= cutoff_time
            ).all()

            if http_requests:
                features['zeek_http_requests'] = len(http_requests)

                # Diversidad de métodos HTTP
                methods = set(h.method for h in http_requests if h.method)
                features['zeek_http_methods_diversity'] = len(methods)

                # User agents sospechosos
                suspicious_ua_patterns = [
                    'sqlmap', 'nikto', 'nmap', 'scanner', 'bot', 'crawler',
                    'python-requests', 'curl', 'wget', 'masscan'
                ]
                features['zeek_suspicious_user_agents'] = sum(
                    1 for h in http_requests
                    if h.user_agent and any(
                        pattern in h.user_agent.lower()
                        for pattern in suspicious_ua_patterns
                    )
                )

            # === SSL ===
            ssl_conns = session.query(ZeekSSL).filter(
                ZeekSSL.source_ip == ip_address,
                ZeekSSL.timestamp >= cutoff_time
            ).all()

            if ssl_conns:
                features['zeek_ssl_connections'] = len(ssl_conns)

                # Certificados inválidos/autofirmados
                features['zeek_ssl_invalid_certs'] = sum(
                    1 for s in ssl_conns
                    if s.validation_status and 'invalid' in s.validation_status.lower()
                )

        except Exception as e:
            print(f"Error extrayendo features de Zeek para {ip_address}: {e}")

        finally:
            session.close()

        return features

    def create_security_event_from_zeek(self, event_type, severity, source_ip,
                                       target_port=None, details='', data=None):
        """
        Crear un evento de seguridad desde una detección de Zeek

        Args:
            event_type: Tipo de evento ('port_scan', 'dns_tunneling', 'beaconing', etc.)
            severity: 'low', 'medium', 'high', 'critical'
            source_ip: IP origen
            target_port: Puerto objetivo (opcional)
            details: Descripción del evento
            data: Datos adicionales en formato dict

        Returns:
            int: ID del evento creado o None si hubo error
        """
        try:
            session = self.db.get_session()

            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                target_port=target_port,
                protocol='tcp',
                attack_vector='network_scan' if 'scan' in event_type else 'suspicious_traffic',
                details=details,
                payload=str(data) if data else None,
                is_blocked=False,
                blocked_by='zeek_detection',
                false_positive=False
            )

            session.add(event)
            session.commit()

            event_id = event.id
            session.close()

            print(f"[Zeek→ML] Evento creado: {event_type} desde {source_ip} (ID: {event_id})")
            return event_id

        except Exception as e:
            print(f"Error creando evento de seguridad desde Zeek: {e}")
            return None

    def process_zeek_detections_to_events(self, hours_back=1):
        """
        Procesar detecciones de Zeek y crear eventos automáticamente

        Args:
            hours_back: Horas hacia atrás para analizar

        Returns:
            dict: Resumen de eventos creados
        """
        from modules.zeek_detections import ZeekDetections

        zeek_detections = ZeekDetections(self.db)

        events_created = {
            'port_scans': 0,
            'dns_tunneling': 0,
            'dga_domains': 0,
            'beaconing': 0,
            'ssl_issues': 0,
            'total': 0
        }

        # === 1. PORT SCANS ===
        port_scans = zeek_detections.detect_port_scan_from_conn_log(
            hours_back=hours_back,
            min_ports=15
        )

        for scan in port_scans.get('port_scans', []):
            event_id = self.create_security_event_from_zeek(
                event_type='port_scan',
                severity=scan['severity'],
                source_ip=scan['ip'],
                details=f"Port scan detectado: {scan['unique_ports']} puertos escaneados "
                       f"en {scan['time_window']} minutos. Scan rate: {scan['scan_rate']:.2f} puertos/min",
                data={
                    'ports_scanned': scan['unique_ports'],
                    'scan_rate': scan['scan_rate'],
                    'time_window': scan['time_window']
                }
            )
            if event_id:
                events_created['port_scans'] += 1

                # DISPARAR ALERTA
                if self.alert_manager:
                    try:
                        self.alert_manager.process_alert({
                            'type': 'zeek_detection',
                            'detection_type': 'port_scan',
                            'severity': scan['severity'].upper(),
                            'ip': scan['ip'],
                            'ports_count': scan['unique_ports'],
                            'protocol': 'tcp',
                            'reason': f"Port scan detectado: {scan['unique_ports']} puertos",
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    except Exception as e:
                        print(f"Error disparando alerta de port scan: {e}")

        # === 2. DNS TUNNELING ===
        dns_analysis = zeek_detections.analyze_dns_queries(hours_back=hours_back * 24)

        # DNS Tunneling
        for tunnel in dns_analysis.get('tunneling', []):
            event_id = self.create_security_event_from_zeek(
                event_type='dns_tunneling',
                severity='high',
                source_ip=tunnel['ip'],
                target_port=53,
                details=f"DNS tunneling detectado: {tunnel['query']} "
                       f"({tunnel['query_length']} caracteres, {tunnel['subdomain_count']} subdominios)",
                data={
                    'domain': tunnel['query'],
                    'query_length': tunnel['query_length'],
                    'subdomain_count': tunnel['subdomain_count']
                }
            )
            if event_id:
                events_created['dns_tunneling'] += 1

                # DISPARAR ALERTA
                if self.alert_manager:
                    try:
                        self.alert_manager.process_alert({
                            'type': 'zeek_detection',
                            'detection_type': 'dns_tunneling',
                            'severity': 'HIGH',
                            'ip': tunnel['ip'],
                            'domains_count': 1,
                            'queries': tunnel['query'],
                            'reason': f"DNS tunneling: {tunnel['query']} ({tunnel['query_length']} chars)",
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    except Exception as e:
                        print(f"Error disparando alerta de DNS tunneling: {e}")

        # DGA (Domain Generation Algorithm)
        for dga in dns_analysis.get('dga', []):
            event_id = self.create_security_event_from_zeek(
                event_type='dga_domain',
                severity='medium',
                source_ip=dga['ip'],
                target_port=53,
                details=f"Dominio DGA detectado: {dga['query']} (entropía: {dga['entropy']})",
                data={
                    'domain': dga['query'],
                    'entropy': dga['entropy']
                }
            )
            if event_id:
                events_created['dga_domains'] += 1

                # DISPARAR ALERTA
                if self.alert_manager:
                    try:
                        self.alert_manager.process_alert({
                            'type': 'zeek_detection',
                            'detection_type': 'dga_domain',
                            'severity': 'MEDIUM',
                            'ip': dga['ip'],
                            'domains_count': 1,
                            'queries': dga['query'],
                            'entropy': dga['entropy'],
                            'reason': f"Dominio DGA detectado: {dga['query']} (entropia: {dga['entropy']:.2f})",
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    except Exception as e:
                        print(f"Error disparando alerta de DGA: {e}")

        # === 3. BEACONING (C&C) ===
        beaconing = zeek_detections.detect_beaconing(
            hours_back=hours_back * 24,
            regularity_threshold=0.8
        )

        for beacon in beaconing.get('beacons', []):
            event_id = self.create_security_event_from_zeek(
                event_type='beaconing',
                severity='critical',
                source_ip=beacon['source_ip'],
                details=f"Beaconing detectado a {beacon['dest_ip']}:{beacon['dest_port']} "
                       f"({beacon['connection_count']} conexiones, "
                       f"regularidad: {beacon['regularity']:.2%})",
                data={
                    'dest_ip': beacon['dest_ip'],
                    'dest_port': beacon['dest_port'],
                    'connection_count': beacon['connection_count'],
                    'regularity': beacon['regularity']
                }
            )
            if event_id:
                events_created['beaconing'] += 1

                # DISPARAR ALERTA
                if self.alert_manager:
                    try:
                        self.alert_manager.process_alert({
                            'type': 'zeek_detection',
                            'detection_type': 'beaconing',
                            'severity': 'CRITICAL',
                            'ip': beacon['source_ip'],
                            'dest_ip': beacon['dest_ip'],
                            'dest_port': beacon['dest_port'],
                            'connection_count': beacon['connection_count'],
                            'regularity': beacon['regularity'],
                            'reason': f"Beaconing (C&C) a {beacon['dest_ip']}:{beacon['dest_port']} ({beacon['connection_count']} conexiones)",
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    except Exception as e:
                        print(f"Error disparando alerta de beaconing: {e}")

        # === 4. SSL ISSUES ===
        ssl_analysis = zeek_detections.analyze_ssl_certificates(hours_back=hours_back * 24)

        # Certificados autofirmados
        for cert in ssl_analysis.get('self_signed', []):
            event_id = self.create_security_event_from_zeek(
                event_type='ssl_self_signed',
                severity='medium',
                source_ip=cert['source_ip'],
                target_port=443,
                details=f"Certificado SSL autofirmado: {cert['server_name']}",
                data={
                    'server_name': cert['server_name'],
                    'issuer': cert['issuer']
                }
            )
            if event_id:
                events_created['ssl_issues'] += 1

                # DISPARAR ALERTA
                if self.alert_manager:
                    try:
                        self.alert_manager.process_alert({
                            'type': 'zeek_detection',
                            'detection_type': 'ssl_self_signed',
                            'severity': 'MEDIUM',
                            'ip': cert['source_ip'],
                            'server_name': cert['server_name'],
                            'issuer': cert['issuer'],
                            'reason': f"Certificado SSL autofirmado: {cert['server_name']}",
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    except Exception as e:
                        print(f"Error disparando alerta de SSL: {e}")

        # Total
        events_created['total'] = sum([
            events_created['port_scans'],
            events_created['dns_tunneling'],
            events_created['dga_domains'],
            events_created['beaconing'],
            events_created['ssl_issues']
        ])

        return events_created


# === FUNCIÓN PARA TASK SCHEDULER ===

def zeek_auto_detect_and_create_events(hours_back=1):
    """
    Función wrapper para ejecutar desde task scheduler

    Args:
        hours_back: Horas hacia atrás para analizar

    Returns:
        dict: Resumen de eventos creados
    """
    from database.db_manager import DatabaseManager

    db = DatabaseManager()
    integration = ZeekMLIntegration(db)

    result = integration.process_zeek_detections_to_events(hours_back=hours_back)

    return {
        'success': True,
        'message': f"Procesadas detecciones de Zeek. {result['total']} eventos creados.",
        'records_processed': result['total'],
        'records_created': result['total'],
        'port_scans': result['port_scans'],
        'dns_tunneling': result['dns_tunneling'],
        'dga_domains': result['dga_domains'],
        'beaconing': result['beaconing'],
        'ssl_issues': result['ssl_issues']
    }
