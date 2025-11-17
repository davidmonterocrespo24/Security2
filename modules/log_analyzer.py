"""
Analizador de Logs del Sistema
"""
import re
import os
from datetime import datetime, timedelta
from collections import Counter


class LogAnalyzer:
    def __init__(self, db_manager=None, attack_detector=None):
        self.db = db_manager
        self.detector = attack_detector
        self.ssh_log_path = '/var/log/auth.log'
        self.nginx_access_log = '/var/log/nginx/access.log'
        self.nginx_error_log = '/var/log/nginx/error.log'

        # Patrones de ataque comunes
        self.attack_patterns = {
            'sql_injection': [
                r'union.*select', r'select.*from', r'insert.*into',
                r'delete.*from', r'drop.*table', r'\'.*or.*\'',
                r'--', r';.*exec', r'xp_cmdshell'
            ],
            'xss': [
                r'<script', r'javascript:', r'onerror=', r'onload=',
                r'<iframe', r'eval\(', r'alert\('
            ],
            'path_traversal': [
                r'\.\./\.\./\.\./etc/passwd', r'\.\./\.\./windows',
                r'\.\./', r'%2e%2e', r'/etc/passwd', r'/etc/shadow'
            ],
            'command_injection': [
                r';.*ls', r'\|.*cat', r'`.*`', r'\$\(.*\)',
                r'&&.*rm', r'nc.*-e', r'bash.*-i'
            ],
            'scanner': [
                r'nikto', r'sqlmap', r'nmap', r'masscan',
                r'acunetix', r'nessus', r'burp', r'metasploit'
            ],
            'exploit': [
                r'shell\.php', r'c99\.php', r'r57\.php',
                r'cmd\.exe', r'eval-stdin\.php', r'\.git/config'
            ]
        }

    def _read_log_file(self, file_path, limit=1000):
        """Leer archivo de log"""
        if not os.path.exists(file_path):
            return []

        try:
            with open(file_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                return lines[-limit:] if len(lines) > limit else lines
        except Exception as e:
            print(f"Error reading log file {file_path}: {e}")
            return []

    def get_ssh_logs(self, limit=100):
        """Obtener logs de SSH"""
        lines = self._read_log_file(self.ssh_log_path, limit)

        logs = []
        for line in lines:
            # Parsear líneas de autenticación SSH
            if 'sshd' in line.lower():
                log_entry = {
                    'raw': line.strip(),
                    'type': 'ssh'
                }

                # Extraer información
                if 'Failed password' in line:
                    log_entry['status'] = 'failed'
                    match = re.search(r'for (\w+) from ([\d.]+)', line)
                    if match:
                        log_entry['user'] = match.group(1)
                        log_entry['ip'] = match.group(2)
                elif 'Accepted password' in line or 'Accepted publickey' in line:
                    log_entry['status'] = 'success'
                    match = re.search(r'for (\w+) from ([\d.]+)', line)
                    if match:
                        log_entry['user'] = match.group(1)
                        log_entry['ip'] = match.group(2)
                elif 'Invalid user' in line:
                    log_entry['status'] = 'invalid_user'
                    match = re.search(r'Invalid user (\w+) from ([\d.]+)', line)
                    if match:
                        log_entry['user'] = match.group(1)
                        log_entry['ip'] = match.group(2)

                # Extraer timestamp
                timestamp_match = re.search(r'(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})', line)
                if timestamp_match:
                    log_entry['timestamp'] = timestamp_match.group(1)

                logs.append(log_entry)

        return logs

    def get_nginx_logs(self, limit=100, log_type='access'):
        """Obtener logs de Nginx"""
        log_path = self.nginx_access_log if log_type == 'access' else self.nginx_error_log
        lines = self._read_log_file(log_path, limit)

        logs = []
        for line in lines:
            if log_type == 'access':
                # Parsear log de acceso de Nginx (formato común)
                # 192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234
                match = re.match(
                    r'([\d.]+) - - \[(.*?)\] "(\w+) (.*?) HTTP/[\d.]+" (\d+) (\d+) "(.*?)" "(.*?)"',
                    line
                )
                if match:
                    logs.append({
                        'ip': match.group(1),
                        'timestamp': match.group(2),
                        'method': match.group(3),
                        'path': match.group(4),
                        'status': int(match.group(5)),
                        'size': int(match.group(6)),
                        'referrer': match.group(7),
                        'user_agent': match.group(8),
                        'type': 'nginx_access'
                    })
            else:
                logs.append({
                    'raw': line.strip(),
                    'type': 'nginx_error'
                })

        return logs

    def get_failed_ssh_count(self, hours=24):
        """Obtener cantidad de intentos fallidos de SSH"""
        logs = self.get_ssh_logs(limit=10000)
        failed = [log for log in logs if log.get('status') == 'failed']
        return len(failed)

    def get_recent_ssh_failures(self, limit=10):
        """Obtener fallos recientes de SSH"""
        logs = self.get_ssh_logs(limit=1000)
        failed = [log for log in logs if log.get('status') in ['failed', 'invalid_user']]
        return failed[-limit:]

    def get_suspicious_requests_count(self):
        """Obtener cantidad de peticiones sospechosas HTTP"""
        logs = self.get_nginx_logs(limit=10000)

        suspicious_count = 0
        suspicious_patterns = [
            r'/\.env',
            r'/admin',
            r'/wp-admin',
            r'/phpmyadmin',
            r'\.php$',
            r'/xmlrpc',
            r'/\.git',
            r'sql',
            r'union.*select',
            r'<script',
            r'javascript:',
        ]

        for log in logs:
            path = log.get('path', '')
            for pattern in suspicious_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    suspicious_count += 1
                    break

        return suspicious_count

    def analyze_patterns(self, log_type='all'):
        """Analizar patrones en los logs"""
        analysis = {
            'ssh': {},
            'nginx': {},
            'threats': []
        }

        # Analizar SSH
        if log_type in ['all', 'ssh']:
            ssh_logs = self.get_ssh_logs(limit=5000)

            # IPs con más intentos fallidos
            failed_ips = [log.get('ip') for log in ssh_logs if log.get('status') == 'failed' and log.get('ip')]
            ip_counter = Counter(failed_ips)

            # Usuarios intentados
            failed_users = [log.get('user') for log in ssh_logs if log.get('status') in ['failed', 'invalid_user'] and log.get('user')]
            user_counter = Counter(failed_users)

            analysis['ssh'] = {
                'total_attempts': len(ssh_logs),
                'failed_attempts': len([l for l in ssh_logs if l.get('status') == 'failed']),
                'successful_attempts': len([l for l in ssh_logs if l.get('status') == 'success']),
                'top_attacking_ips': ip_counter.most_common(10),
                'top_attempted_users': user_counter.most_common(10)
            }

            # Detectar amenazas SSH
            for ip, count in ip_counter.most_common(20):
                if count > 10:
                    analysis['threats'].append({
                        'type': 'ssh_bruteforce',
                        'ip': ip,
                        'attempts': count,
                        'severity': 'high' if count > 50 else 'medium'
                    })

        # Analizar Nginx
        if log_type in ['all', 'nginx']:
            nginx_logs = self.get_nginx_logs(limit=5000)

            # IPs con más peticiones
            all_ips = [log.get('ip') for log in nginx_logs if log.get('ip')]
            ip_counter = Counter(all_ips)

            # Peticiones por código de estado
            status_codes = [log.get('status') for log in nginx_logs if log.get('status')]
            status_counter = Counter(status_codes)

            # Peticiones sospechosas
            suspicious_logs = []
            suspicious_patterns = [
                (r'/\.env', 'env_file_access'),
                (r'/admin', 'admin_scan'),
                (r'/wp-admin', 'wordpress_scan'),
                (r'/phpmyadmin', 'phpmyadmin_scan'),
                (r'\.php$', 'php_file_scan'),
                (r'/xmlrpc', 'xmlrpc_attack'),
                (r'sql|union.*select', 'sql_injection'),
                (r'<script|javascript:', 'xss_attempt'),
            ]

            for log in nginx_logs:
                path = log.get('path', '')
                for pattern, threat_type in suspicious_patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        suspicious_logs.append({
                            'log': log,
                            'threat_type': threat_type
                        })
                        break

            analysis['nginx'] = {
                'total_requests': len(nginx_logs),
                'unique_ips': len(set(all_ips)),
                'status_codes': dict(status_counter),
                'top_ips': ip_counter.most_common(10),
                'suspicious_requests': len(suspicious_logs)
            }

            # Detectar scraping excesivo
            for ip, count in ip_counter.most_common(20):
                if count > 100:
                    analysis['threats'].append({
                        'type': 'possible_scraping',
                        'ip': ip,
                        'requests': count,
                        'severity': 'high' if count > 500 else 'medium'
                    })

            # Agrupar amenazas por tipo
            threat_types = Counter([s['threat_type'] for s in suspicious_logs])
            for threat_type, count in threat_types.items():
                if count > 5:
                    analysis['threats'].append({
                        'type': threat_type,
                        'count': count,
                        'severity': 'high' if count > 20 else 'medium'
                    })

        return analysis

    def detect_brute_force(self, ip_threshold=10, time_window_minutes=60):
        """Detectar ataques de fuerza bruta"""
        ssh_logs = self.get_ssh_logs(limit=5000)

        # Agrupar por IP
        ip_attempts = {}
        for log in ssh_logs:
            if log.get('status') == 'failed' and log.get('ip'):
                ip = log['ip']
                if ip not in ip_attempts:
                    ip_attempts[ip] = []
                ip_attempts[ip].append(log)

        # Detectar IPs con muchos intentos
        brute_force_ips = []
        for ip, attempts in ip_attempts.items():
            if len(attempts) >= ip_threshold:
                brute_force_ips.append({
                    'ip': ip,
                    'attempts': len(attempts),
                    'users': list(set([a.get('user', 'unknown') for a in attempts]))
                })

        return brute_force_ips

    def detect_attack_type(self, request_path, user_agent=''):
        """Detectar tipo de ataque basado en patrones"""
        text = f"{request_path} {user_agent}".lower()
        detected_attacks = []

        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    break

        return detected_attacks

    def determine_severity(self, status_code, attack_types, failed_count=0):
        """Determinar severidad basada en múltiples factores"""
        if 'command_injection' in attack_types or 'exploit' in attack_types:
            return 'critical'

        if 'sql_injection' in attack_types or 'path_traversal' in attack_types:
            return 'high'

        if 'xss' in attack_types or 'scanner' in attack_types:
            return 'high'

        if failed_count >= 10:
            return 'critical'
        elif failed_count >= 5:
            return 'high'
        elif failed_count >= 3:
            return 'medium'

        if status_code >= 500:
            return 'medium'
        elif status_code == 404:
            return 'low'
        elif status_code >= 400:
            return 'medium'

        return 'low'

    def parse_nginx_timestamp(self, time_str):
        """Convertir timestamp de Nginx a datetime"""
        try:
            # Formato: 24/Jan/2024:10:30:45 +0000
            dt = datetime.strptime(time_str.split()[0], '%d/%b/%Y:%H:%M:%S')
            return dt
        except:
            return datetime.utcnow()

    def parse_ssh_timestamp(self, time_str, year=None):
        """Convertir timestamp de SSH auth.log a datetime"""
        try:
            # Formato: Jan 24 10:30:45
            if not year:
                year = datetime.utcnow().year
            dt = datetime.strptime(f"{year} {time_str}", '%Y %b %d %H:%M:%S')
            return dt
        except:
            return datetime.utcnow()

    def import_nginx_access_logs(self, log_file_path=None, limit=None):
        """Importar logs de Nginx access.log y crear eventos de seguridad"""
        if not self.db:
            return {'success': False, 'error': 'Database manager not initialized'}

        if not log_file_path:
            log_file_path = self.nginx_access_log

        if not os.path.exists(log_file_path):
            return {'success': False, 'error': f'File not found: {log_file_path}'}

        events_created = 0
        events_skipped = 0
        errors = []
        from collections import defaultdict
        ip_stats = defaultdict(lambda: {'requests': 0, 'attacks': 0})

        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    if limit and line_num > limit:
                        break

                    line = line.strip()
                    if not line:
                        continue

                    # Parsear línea de access.log
                    # Formato: IP - - [timestamp] "METHOD path HTTP/x.x" status size "referrer" "user_agent"
                    match = re.match(
                        r'([\d.]+) - - \[(.*?)\] "(\w+) (.*?) HTTP/[\d.]+" (\d+) (\d+) "(.*?)" "(.*?)"',
                        line
                    )

                    if not match:
                        events_skipped += 1
                        continue

                    ip_address = match.group(1)
                    timestamp_str = match.group(2)
                    method = match.group(3)
                    path = match.group(4)
                    status = int(match.group(5))
                    user_agent = match.group(8)

                    ip_stats[ip_address]['requests'] += 1

                    # Detectar ataques en la ruta y user agent
                    attack_types = self.detect_attack_type(path, user_agent)

                    # Solo crear evento si hay ataque o error HTTP
                    if attack_types or status >= 400:
                        severity = self.determine_severity(status, attack_types)

                        if attack_types:
                            event_type = 'http_attack'
                            attack_vector = ','.join(attack_types)
                            description = f"Attack detected: {', '.join(attack_types)}"
                            ip_stats[ip_address]['attacks'] += 1
                        elif status == 404:
                            event_type = 'http_404'
                            attack_vector = 'scan'
                            description = f"404 Not Found: {path[:100]}"
                        elif status >= 400:
                            event_type = 'http_error'
                            attack_vector = 'error'
                            description = f"HTTP {status} error"
                        else:
                            events_skipped += 1
                            continue

                        try:
                            timestamp = self.parse_nginx_timestamp(timestamp_str)
                            self.db.log_security_event(
                                event_type=event_type,
                                severity=severity,
                                source_ip=ip_address,
                                protocol='http',
                                request_method=method,
                                request_path=path[:500],
                                user_agent=user_agent[:500],
                                attack_vector=attack_vector,
                                description=description,
                                timestamp=timestamp
                            )
                            events_created += 1
                        except Exception as e:
                            errors.append(f"Line {line_num}: {str(e)[:100]}")
                    else:
                        events_skipped += 1

        except Exception as e:
            return {'success': False, 'error': f'Error reading file: {str(e)}'}

        # Identificar IPs sospechosas
        suspicious_ips = [
            {'ip': ip, 'requests': stats['requests'], 'attacks': stats['attacks']}
            for ip, stats in ip_stats.items()
            if stats['requests'] > 100 or stats['attacks'] > 5
        ]

        return {
            'success': True,
            'events_created': events_created,
            'events_skipped': events_skipped,
            'errors': errors[:10],
            'suspicious_ips': suspicious_ips[:20],
            'total_lines': line_num
        }

    def import_ssh_auth_logs(self, log_file_path=None, limit=None):
        """Importar logs de SSH auth.log y crear eventos de seguridad"""
        if not self.db:
            return {'success': False, 'error': 'Database manager not initialized'}

        if not log_file_path:
            log_file_path = self.ssh_log_path

        if not os.path.exists(log_file_path):
            return {'success': False, 'error': f'File not found: {log_file_path}'}

        events_created = 0
        events_skipped = 0
        errors = []
        from collections import defaultdict
        failed_attempts = defaultdict(list)
        year = datetime.utcnow().year

        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    if limit and line_num > limit:
                        break

                    line = line.strip()
                    if not line or 'sshd' not in line:
                        continue

                    # Detectar login fallido
                    match_failed = re.search(
                        r'(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}).*?'
                        r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)',
                        line
                    )

                    if match_failed:
                        time_str = match_failed.group(1)
                        username = match_failed.group(2)
                        ip_address = match_failed.group(3)
                        timestamp = self.parse_ssh_timestamp(time_str, year)

                        failed_attempts[ip_address].append(timestamp)
                        recent_failures = len([
                            t for t in failed_attempts[ip_address]
                            if t > datetime.utcnow() - timedelta(minutes=10)
                        ])

                        severity = self.determine_severity(0, [], recent_failures)
                        event_type = 'ssh_brute_force' if recent_failures >= 5 else 'ssh_failed_login'

                        try:
                            self.db.log_security_event(
                                event_type=event_type,
                                severity=severity,
                                source_ip=ip_address,
                                protocol='ssh',
                                attack_vector='brute_force' if recent_failures >= 5 else 'auth_failure',
                                description=f"Failed SSH login for user '{username}' (attempt {recent_failures})",
                                details=f"username: {username}",
                                timestamp=timestamp
                            )
                            events_created += 1
                        except Exception as e:
                            errors.append(f"Line {line_num}: {str(e)[:100]}")
                        continue

                    # Detectar login exitoso
                    match_success = re.search(
                        r'(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}).*?'
                        r'Accepted (\w+) for (\S+) from ([\d.]+)',
                        line
                    )

                    if match_success:
                        time_str = match_success.group(1)
                        auth_method = match_success.group(2)
                        username = match_success.group(3)
                        ip_address = match_success.group(4)
                        timestamp = self.parse_ssh_timestamp(time_str, year)

                        try:
                            self.db.log_security_event(
                                event_type='ssh_successful_login',
                                severity='low',
                                source_ip=ip_address,
                                protocol='ssh',
                                attack_vector='auth_success',
                                description=f"Successful SSH login for user '{username}' via {auth_method}",
                                details=f"username: {username}, method: {auth_method}",
                                timestamp=timestamp
                            )
                            events_created += 1
                        except Exception as e:
                            errors.append(f"Line {line_num}: {str(e)[:100]}")
                        continue

                    # Detectar usuario inválido
                    match_invalid = re.search(
                        r'(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}).*?'
                        r'Invalid user (\S+) from ([\d.]+)',
                        line
                    )

                    if match_invalid:
                        time_str = match_invalid.group(1)
                        username = match_invalid.group(2)
                        ip_address = match_invalid.group(3)
                        timestamp = self.parse_ssh_timestamp(time_str, year)

                        try:
                            self.db.log_security_event(
                                event_type='ssh_invalid_user',
                                severity='medium',
                                source_ip=ip_address,
                                protocol='ssh',
                                attack_vector='scan',
                                description=f"SSH attempt with invalid user '{username}'",
                                details=f"username: {username}",
                                timestamp=timestamp
                            )
                            events_created += 1
                        except Exception as e:
                            errors.append(f"Line {line_num}: {str(e)[:100]}")
                        continue

        except Exception as e:
            return {'success': False, 'error': f'Error reading file: {str(e)}'}

        brute_force_ips = [
            {'ip': ip, 'failed_attempts': len(attempts)}
            for ip, attempts in failed_attempts.items()
            if len(attempts) >= 5
        ]

        return {
            'success': True,
            'events_created': events_created,
            'events_skipped': events_skipped,
            'errors': errors[:10],
            'brute_force_ips': brute_force_ips[:20],
            'total_lines': line_num
        }

    def batch_import_logs(self, nginx_access=None, nginx_error=None, ssh_auth=None, limit_per_file=None):
        """Importar múltiples archivos de logs de una vez"""
        results = {
            'total_events': 0,
            'logs_processed': []
        }

        if nginx_access:
            result = self.import_nginx_access_logs(nginx_access, limit=limit_per_file)
            results['logs_processed'].append({
                'type': 'nginx_access',
                'path': nginx_access,
                'result': result
            })
            if result.get('success'):
                results['total_events'] += result.get('events_created', 0)

        if ssh_auth:
            result = self.import_ssh_auth_logs(ssh_auth, limit=limit_per_file)
            results['logs_processed'].append({
                'type': 'ssh_auth',
                'path': ssh_auth,
                'result': result
            })
            if result.get('success'):
                results['total_events'] += result.get('events_created', 0)

        return results

    def get_available_log_files(self):
        """Detectar archivos de logs disponibles en el sistema"""
        log_paths = {
            'nginx_access': [
                '/var/log/nginx/access.log',
                '/var/log/nginx/access.log.1',
                '/usr/local/nginx/logs/access.log',
                'C:\\nginx\\logs\\access.log'
            ],
            'nginx_error': [
                '/var/log/nginx/error.log',
                '/var/log/nginx/error.log.1',
                '/usr/local/nginx/logs/error.log',
                'C:\\nginx\\logs\\error.log'
            ],
            'ssh_auth': [
                '/var/log/auth.log',
                '/var/log/auth.log.1',
                '/var/log/secure',
                '/var/log/secure.1'
            ]
        }

        available = {}
        for log_type, paths in log_paths.items():
            for path in paths:
                if os.path.exists(path):
                    available[log_type] = {
                        'path': path,
                        'size': os.path.getsize(path),
                        'modified': datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                    }
                    break

        return available
