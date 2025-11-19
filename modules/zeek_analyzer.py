"""
Módulo de análisis de logs de Zeek
Parser de logs JSON, importación a BD, detecciones avanzadas
"""

import json
import os
import math
from datetime import datetime
from collections import Counter, defaultdict


class ZeekLogParser:
    """Parser de logs JSON de Zeek"""

    @staticmethod
    def parse_json_log(log_file_path, limit=None):
        """
        Parsear archivo de log JSON de Zeek

        Args:
            log_file_path: Ruta al archivo .log
            limit: Número máximo de líneas a leer

        Returns:
            list: Lista de eventos parseados
        """
        events = []

        if not os.path.exists(log_file_path):
            return events

        try:
            with open(log_file_path, 'r') as f:
                count = 0
                for line in f:
                    if limit and count >= limit:
                        break

                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    try:
                        event = json.loads(line)
                        events.append(event)
                        count += 1
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            print(f"Error leyendo {log_file_path}: {e}")

        return events

    @staticmethod
    def parse_conn_log(log_file_path, limit=None):
        """Parsear conn.log (conexiones)"""
        events = ZeekLogParser.parse_json_log(log_file_path, limit)

        connections = []
        for event in events:
            conn = {
                'timestamp': ZeekLogParser._parse_timestamp(event.get('ts')),
                'uid': event.get('uid'),
                'source_ip': event.get('id.orig_h'),
                'source_port': event.get('id.orig_p'),
                'dest_ip': event.get('id.resp_h'),
                'dest_port': event.get('id.resp_p'),
                'protocol': event.get('proto'),
                'service': event.get('service'),
                'duration': event.get('duration'),
                'orig_bytes': event.get('orig_bytes', 0),
                'resp_bytes': event.get('resp_bytes', 0),
                'conn_state': event.get('conn_state'),
                'orig_pkts': event.get('orig_pkts', 0),
                'resp_pkts': event.get('resp_pkts', 0),
                'local_orig': event.get('local_orig', False),
                'local_resp': event.get('local_resp', False),
                'history': event.get('history')
            }
            connections.append(conn)

        return connections

    @staticmethod
    def parse_dns_log(log_file_path, limit=None):
        """Parsear dns.log (queries DNS)"""
        events = ZeekLogParser.parse_json_log(log_file_path, limit)

        dns_queries = []
        for event in events:
            query = {
                'timestamp': ZeekLogParser._parse_timestamp(event.get('ts')),
                'uid': event.get('uid'),
                'source_ip': event.get('id.orig_h'),
                'dest_ip': event.get('id.resp_h'),
                'query': event.get('query'),
                'query_type': event.get('qtype_name'),
                'query_class': event.get('qclass_name'),
                'rcode': event.get('rcode'),
                'rcode_name': event.get('rcode_name'),
                'answers': json.dumps(event.get('answers', [])),
                'ttls': json.dumps(event.get('TTLs', [])),
                'AA': event.get('AA', False),
                'TC': event.get('TC', False),
                'RD': event.get('RD', False),
                'RA': event.get('RA', False)
            }
            dns_queries.append(query)

        return dns_queries

    @staticmethod
    def parse_ssl_log(log_file_path, limit=None):
        """Parsear ssl.log (conexiones SSL/TLS)"""
        events = ZeekLogParser.parse_json_log(log_file_path, limit)

        ssl_conns = []
        for event in events:
            ssl = {
                'timestamp': ZeekLogParser._parse_timestamp(event.get('ts')),
                'uid': event.get('uid'),
                'source_ip': event.get('id.orig_h'),
                'dest_ip': event.get('id.resp_h'),
                'dest_port': event.get('id.resp_p'),
                'version': event.get('version'),
                'cipher': event.get('cipher'),
                'curve': event.get('curve'),
                'server_name': event.get('server_name'),
                'subject': event.get('subject'),
                'issuer': event.get('issuer'),
                'validation_status': event.get('validation_status'),
                'cert_chain_fuids': json.dumps(event.get('cert_chain_fuids', [])),
                'client_cert_chain_fuids': json.dumps(event.get('client_cert_chain_fuids', [])),
                'not_valid_before': ZeekLogParser._parse_timestamp(event.get('not_valid_before')),
                'not_valid_after': ZeekLogParser._parse_timestamp(event.get('not_valid_after')),
                'ja3': event.get('ja3'),
                'ja3s': event.get('ja3s')
            }
            ssl_conns.append(ssl)

        return ssl_conns

    @staticmethod
    def parse_http_log(log_file_path, limit=None):
        """Parsear http.log (tráfico HTTP)"""
        events = ZeekLogParser.parse_json_log(log_file_path, limit)

        http_requests = []
        for event in events:
            http = {
                'timestamp': ZeekLogParser._parse_timestamp(event.get('ts')),
                'uid': event.get('uid'),
                'source_ip': event.get('id.orig_h'),
                'dest_ip': event.get('id.resp_h'),
                'dest_port': event.get('id.resp_p'),
                'method': event.get('method'),
                'host': event.get('host'),
                'uri': event.get('uri'),
                'referrer': event.get('referrer'),
                'user_agent': event.get('user_agent'),
                'status_code': event.get('status_code'),
                'status_msg': event.get('status_msg'),
                'request_body_len': event.get('request_body_len', 0),
                'response_body_len': event.get('response_body_len', 0),
                'resp_mime_types': json.dumps(event.get('resp_mime_types', [])),
                'tags': json.dumps(event.get('tags', []))
            }
            http_requests.append(http)

        return http_requests

    @staticmethod
    def parse_files_log(log_file_path, limit=None):
        """Parsear files.log (archivos transferidos)"""
        events = ZeekLogParser.parse_json_log(log_file_path, limit)

        files = []
        for event in events:
            file_info = {
                'timestamp': ZeekLogParser._parse_timestamp(event.get('ts')),
                'fuid': event.get('fuid'),
                'conn_uids': json.dumps(event.get('conn_uids', [])),
                'source_ip': event.get('tx_hosts', [None])[0] if event.get('tx_hosts') else None,
                'dest_ip': event.get('rx_hosts', [None])[0] if event.get('rx_hosts') else None,
                'filename': event.get('filename'),
                'mime_type': event.get('mime_type'),
                'total_bytes': event.get('total_bytes'),
                'seen_bytes': event.get('seen_bytes'),
                'missing_bytes': event.get('missing_bytes'),
                'md5': event.get('md5'),
                'sha1': event.get('sha1'),
                'sha256': event.get('sha256'),
                'source_protocol': event.get('source')
            }
            files.append(file_info)

        return files

    @staticmethod
    def parse_notice_log(log_file_path, limit=None):
        """Parsear notice.log (alertas de Zeek)"""
        events = ZeekLogParser.parse_json_log(log_file_path, limit)

        notices = []
        for event in events:
            notice = {
                'timestamp': ZeekLogParser._parse_timestamp(event.get('ts')),
                'uid': event.get('uid'),
                'source_ip': event.get('id.orig_h') or event.get('src'),
                'dest_ip': event.get('id.resp_h') or event.get('dst'),
                'dest_port': event.get('id.resp_p') or event.get('p'),
                'note': event.get('note'),
                'msg': event.get('msg'),
                'sub': event.get('sub'),
                'protocol': event.get('proto'),
                'actions': json.dumps(event.get('actions', [])),
                'file_mime_type': event.get('file_mime_type'),
                'file_desc': event.get('file_desc'),
                'suppress_for': event.get('suppress_for')
            }
            notices.append(notice)

        return notices

    @staticmethod
    def _parse_timestamp(ts):
        """Convertir timestamp de Zeek a datetime"""
        if ts is None:
            return None

        try:
            if isinstance(ts, (int, float)):
                return datetime.fromtimestamp(ts)
            elif isinstance(ts, str):
                return datetime.fromisoformat(ts)
            else:
                return None
        except:
            return None


class ZeekAnalyzer:
    """Analizador de logs de Zeek con detecciones avanzadas"""

    def __init__(self, db_manager):
        self.db = db_manager
        self.parser = ZeekLogParser()

    def import_zeek_logs_to_db(self, log_type='all', limit=None):
        """
        Importar logs de Zeek a la base de datos

        Args:
            log_type: 'conn', 'dns', 'ssl', 'http', 'files', 'notice' o 'all'
            limit: Límite de registros por archivo

        Returns:
            dict: {
                'success': bool,
                'imported': {log_type: count},
                'errors': []
            }
        """
        from modules.zeek_manager import ZeekManager

        zeek_manager = ZeekManager(self.db)
        log_files = zeek_manager.get_log_files()

        imported = {}
        errors = []

        # Importar cada tipo de log
        if log_type == 'all' or log_type == 'conn':
            if 'conn' in log_files:
                try:
                    count = self._import_conn_log(log_files['conn'], limit)
                    imported['conn'] = count
                except Exception as e:
                    errors.append(f"Error importando conn.log: {e}")

        if log_type == 'all' or log_type == 'dns':
            if 'dns' in log_files:
                try:
                    count = self._import_dns_log(log_files['dns'], limit)
                    imported['dns'] = count
                except Exception as e:
                    errors.append(f"Error importando dns.log: {e}")

        if log_type == 'all' or log_type == 'ssl':
            if 'ssl' in log_files:
                try:
                    count = self._import_ssl_log(log_files['ssl'], limit)
                    imported['ssl'] = count
                except Exception as e:
                    errors.append(f"Error importando ssl.log: {e}")

        if log_type == 'all' or log_type == 'http':
            if 'http' in log_files:
                try:
                    count = self._import_http_log(log_files['http'], limit)
                    imported['http'] = count
                except Exception as e:
                    errors.append(f"Error importando http.log: {e}")

        if log_type == 'all' or log_type == 'files':
            if 'files' in log_files:
                try:
                    count = self._import_files_log(log_files['files'], limit)
                    imported['files'] = count
                except Exception as e:
                    errors.append(f"Error importando files.log: {e}")

        if log_type == 'all' or log_type == 'notice':
            if 'notice' in log_files:
                try:
                    count = self._import_notice_log(log_files['notice'], limit)
                    imported['notice'] = count
                except Exception as e:
                    errors.append(f"Error importando notice.log: {e}")

        return {
            'success': len(errors) == 0,
            'imported': imported,
            'errors': errors,
            'total_imported': sum(imported.values())
        }

    def _import_conn_log(self, log_path, limit):
        """Importar conn.log a base de datos"""
        from database.models import ZeekConnection

        connections = self.parser.parse_conn_log(log_path, limit)
        session = self.db.get_session()

        count = 0
        try:
            for conn_data in connections:
                # Verificar si ya existe (por uid)
                uid = conn_data.get('uid')
                if uid:
                    existing = session.query(ZeekConnection).filter_by(uid=uid).first()
                    if existing:
                        continue

                # Crear registro
                conn = ZeekConnection(**conn_data)
                session.add(conn)
                count += 1

                # Commit cada 100 registros
                if count % 100 == 0:
                    session.commit()

            session.commit()
        finally:
            session.close()

        return count

    def _import_dns_log(self, log_path, limit):
        """Importar dns.log a base de datos"""
        from database.models import ZeekDNS

        dns_queries = self.parser.parse_dns_log(log_path, limit)
        session = self.db.get_session()

        count = 0
        try:
            for dns_data in dns_queries:
                # Crear registro
                dns = ZeekDNS(**dns_data)

                # Calcular entropía de la query (detección DGA)
                query = dns_data.get('query', '')
                if query:
                    dns.query_entropy = self._calculate_entropy(query)

                session.add(dns)
                count += 1

                if count % 100 == 0:
                    session.commit()

            session.commit()
        finally:
            session.close()

        return count

    def _import_ssl_log(self, log_path, limit):
        """Importar ssl.log a base de datos"""
        from database.models import ZeekSSL

        ssl_conns = self.parser.parse_ssl_log(log_path, limit)
        session = self.db.get_session()

        count = 0
        try:
            for ssl_data in ssl_conns:
                # Crear registro
                ssl = ZeekSSL(**ssl_data)

                # Análisis de seguridad
                # 1. Certificado auto-firmado
                if ssl_data.get('subject') == ssl_data.get('issuer'):
                    ssl.is_self_signed = True

                # 2. Certificado expirado
                if ssl_data.get('not_valid_after'):
                    if ssl_data['not_valid_after'] < datetime.utcnow():
                        ssl.is_expired = True

                # 3. Versión SSL/TLS débil
                version = ssl_data.get('version', '')
                if any(weak in version for weak in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']):
                    ssl.is_weak_cipher = True

                # Marcar como sospechoso si tiene problemas
                if ssl.is_self_signed or ssl.is_expired or ssl.is_weak_cipher:
                    ssl.is_suspicious = True

                session.add(ssl)
                count += 1

                if count % 100 == 0:
                    session.commit()

            session.commit()
        finally:
            session.close()

        return count

    def _import_http_log(self, log_path, limit):
        """Importar http.log a base de datos"""
        from database.models import ZeekHTTP

        http_requests = self.parser.parse_http_log(log_path, limit)
        session = self.db.get_session()

        count = 0
        try:
            for http_data in http_requests:
                # Crear registro
                http = ZeekHTTP(**http_data)

                # Detectar requests sospechosos
                uri = http_data.get('uri', '')
                user_agent = http_data.get('user_agent', '')

                suspicious_patterns = [
                    '../', '..\\', '<script', 'UNION SELECT', "'; DROP",
                    '/etc/passwd', '/bin/bash', 'cmd.exe'
                ]

                if any(pattern in uri for pattern in suspicious_patterns):
                    http.is_suspicious = True

                if 'nikto' in user_agent.lower() or 'sqlmap' in user_agent.lower():
                    http.is_suspicious = True

                session.add(http)
                count += 1

                if count % 100 == 0:
                    session.commit()

            session.commit()
        finally:
            session.close()

        return count

    def _import_files_log(self, log_path, limit):
        """Importar files.log a base de datos"""
        from database.models import ZeekFiles

        files = self.parser.parse_files_log(log_path, limit)
        session = self.db.get_session()

        count = 0
        try:
            for file_data in files:
                # Verificar si ya existe (por fuid)
                fuid = file_data.get('fuid')
                if fuid:
                    existing = session.query(ZeekFiles).filter_by(fuid=fuid).first()
                    if existing:
                        continue

                # Crear registro
                file_obj = ZeekFiles(**file_data)

                # Detectar tipos de archivo sospechosos
                mime = file_data.get('mime_type', '')
                suspicious_mimes = [
                    'application/x-executable',
                    'application/x-dosexec',
                    'application/x-sh',
                    'text/x-shellscript'
                ]

                if mime in suspicious_mimes:
                    file_obj.is_suspicious = True

                session.add(file_obj)
                count += 1

                if count % 100 == 0:
                    session.commit()

            session.commit()
        finally:
            session.close()

        return count

    def _import_notice_log(self, log_path, limit):
        """Importar notice.log a base de datos"""
        from database.models import ZeekNotice

        notices = self.parser.parse_notice_log(log_path, limit)
        session = self.db.get_session()

        count = 0
        try:
            for notice_data in notices:
                # Crear registro
                notice = ZeekNotice(**notice_data)

                # Mapear severidad basada en el tipo de notice
                note = notice_data.get('note', '')

                if any(critical in note for critical in ['Scan::Port_Scan', 'Malware', 'C&C']):
                    notice.severity = 'critical'
                elif any(high in note for high in ['SSH::Password_Guessing', 'Brute_Force']):
                    notice.severity = 'high'
                elif 'Weird' in note:
                    notice.severity = 'low'
                else:
                    notice.severity = 'medium'

                session.add(notice)
                count += 1

                if count % 100 == 0:
                    session.commit()

            session.commit()
        finally:
            session.close()

        return count

    def detect_port_scan(self, hours_back=24, min_ports=10):
        """
        Detectar escaneos de puertos desde conn.log

        Args:
            hours_back: Horas hacia atrás a analizar
            min_ports: Mínimo de puertos distintos para considerar scan

        Returns:
            list: IPs con posible port scan
        """
        from database.models import ZeekConnection
        from datetime import timedelta

        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            # Obtener conexiones recientes
            conns = session.query(ZeekConnection).filter(
                ZeekConnection.timestamp >= cutoff
            ).all()

            # Agrupar por IP origen
            ip_ports = defaultdict(set)

            for conn in conns:
                source_ip = conn.source_ip
                dest_port = conn.dest_port

                if source_ip and dest_port:
                    ip_ports[source_ip].add(dest_port)

            # Detectar IPs con muchos puertos
            port_scanners = []

            for ip, ports in ip_ports.items():
                if len(ports) >= min_ports:
                    port_scanners.append({
                        'ip': ip,
                        'ports_scanned': len(ports),
                        'ports': sorted(list(ports))[:20]  # Top 20 puertos
                    })

            # Ordenar por cantidad de puertos
            port_scanners.sort(key=lambda x: x['ports_scanned'], reverse=True)

            return port_scanners

        finally:
            session.close()

    def analyze_dns_queries(self, hours_back=24, min_entropy=3.5):
        """
        Analizar queries DNS sospechosas

        Args:
            hours_back: Horas hacia atrás
            min_entropy: Entropía mínima para considerar DGA

        Returns:
            dict: {
                'high_entropy_queries': list,
                'tunneling_suspects': list,
                'nxdomain_spam': list
            }
        """
        from database.models import ZeekDNS
        from datetime import timedelta

        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            queries = session.query(ZeekDNS).filter(
                ZeekDNS.timestamp >= cutoff
            ).all()

            high_entropy = []
            tunneling = []
            nxdomain_ips = defaultdict(int)

            for query in queries:
                # 1. High entropy (DGA detection)
                if query.query_entropy and query.query_entropy >= min_entropy:
                    high_entropy.append({
                        'query': query.query,
                        'entropy': query.query_entropy,
                        'source_ip': query.source_ip
                    })

                # 2. DNS Tunneling (queries muy largas)
                query_str = query.query or ''
                if len(query_str) > 60:
                    tunneling.append({
                        'query': query_str,
                        'length': len(query_str),
                        'source_ip': query.source_ip
                    })

                # 3. NXDOMAIN spam
                if query.rcode_name == 'NXDOMAIN':
                    nxdomain_ips[query.source_ip] += 1

            # IPs con muchos NXDOMAIN
            nxdomain_spam = [
                {'ip': ip, 'nxdomain_count': count}
                for ip, count in nxdomain_ips.items()
                if count >= 50
            ]

            return {
                'high_entropy_queries': high_entropy[:20],
                'tunneling_suspects': tunneling[:20],
                'nxdomain_spam': sorted(nxdomain_spam, key=lambda x: x['nxdomain_count'], reverse=True)
            }

        finally:
            session.close()

    def get_suspicious_connections(self, hours_back=24):
        """Obtener conexiones sospechosas"""
        from database.models import ZeekConnection
        from datetime import timedelta

        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            # Conexiones marcadas como sospechosas
            suspicious = session.query(ZeekConnection).filter(
                ZeekConnection.timestamp >= cutoff,
                ZeekConnection.is_suspicious == True
            ).limit(100).all()

            return [conn.to_dict() for conn in suspicious]

        finally:
            session.close()

    def get_top_connections(self, hours_back=24, limit=10):
        """
        Obtener top conexiones por varios criterios

        Returns:
            dict: {
                'by_bytes': list,
                'by_duration': list,
                'by_packets': list
            }
        """
        from database.models import ZeekConnection
        from datetime import timedelta

        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            conns = session.query(ZeekConnection).filter(
                ZeekConnection.timestamp >= cutoff
            ).all()

            # Top por bytes
            by_bytes = sorted(
                conns,
                key=lambda x: (x.orig_bytes or 0) + (x.resp_bytes or 0),
                reverse=True
            )[:limit]

            # Top por duración
            by_duration = sorted(
                [c for c in conns if c.duration],
                key=lambda x: x.duration,
                reverse=True
            )[:limit]

            # Top por paquetes
            by_packets = sorted(
                conns,
                key=lambda x: (x.orig_pkts or 0) + (x.resp_pkts or 0),
                reverse=True
            )[:limit]

            return {
                'by_bytes': [c.to_dict() for c in by_bytes],
                'by_duration': [c.to_dict() for c in by_duration],
                'by_packets': [c.to_dict() for c in by_packets]
            }

        finally:
            session.close()

    def _calculate_entropy(self, string):
        """Calcular entropía de Shannon de un string"""
        if not string:
            return 0.0

        # Contar frecuencia de caracteres
        char_freq = Counter(string)
        string_len = len(string)

        # Calcular entropía
        entropy = 0.0
        for count in char_freq.values():
            probability = count / string_len
            entropy -= probability * math.log2(probability)

        return round(entropy, 2)


# ==================== FUNCIONES PARA TASK SCHEDULER ====================

def import_zeek_logs(limit=1000):
    """
    Función wrapper para importar logs de Zeek desde el task scheduler

    Args:
        limit: Límite de registros a importar por archivo

    Returns:
        dict: Resultado de la importación
    """
    from database.db_manager import DatabaseManager

    db = DatabaseManager()
    analyzer = ZeekAnalyzer(db)

    result = analyzer.import_zeek_logs_to_db(log_type='all', limit=limit)

    return {
        'success': result['success'],
        'message': f"Importados {result['total_imported']} registros de Zeek",
        'records_processed': result['total_imported'],
        'records_created': result['total_imported'],
        'connections_imported': result['imported'].get('conn', 0),
        'dns_imported': result['imported'].get('dns', 0),
        'http_imported': result['imported'].get('http', 0),
        'ssl_imported': result['imported'].get('ssl', 0),
        'files_imported': result['imported'].get('files', 0),
        'notices_imported': result['imported'].get('notice', 0),
        'errors': result['errors']
    }
