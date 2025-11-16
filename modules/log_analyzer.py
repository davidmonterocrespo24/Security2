"""
Analizador de Logs del Sistema
"""
import re
import os
from datetime import datetime, timedelta
from collections import Counter


class LogAnalyzer:
    def __init__(self):
        self.ssh_log_path = '/var/log/auth.log'
        self.nginx_access_log = '/var/log/nginx/access.log'
        self.nginx_error_log = '/var/log/nginx/error.log'

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
