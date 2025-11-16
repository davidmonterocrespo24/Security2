"""
Detector de Amenazas del Sistema
"""
import os
import re
from datetime import datetime
from .log_analyzer import LogAnalyzer
from .bot_detector import BotDetector


class ThreatDetector:
    def __init__(self):
        self.log_analyzer = LogAnalyzer()
        self.bot_detector = BotDetector()
        self.threats = []

    def scan(self):
        """Escanear en busca de amenazas"""
        self.threats = []

        # 1. Analizar logs en busca de patrones sospechosos
        log_analysis = self.log_analyzer.analyze_patterns('all')

        for threat in log_analysis.get('threats', []):
            self.threats.append({
                'id': len(self.threats) + 1,
                'timestamp': datetime.now().isoformat(),
                'type': threat['type'],
                'severity': threat.get('severity', 'medium'),
                'details': threat,
                'resolved': False
            })

        # 2. Detectar bots maliciosos
        bot_analysis = self.bot_detector.analyze_logs()
        for bot in bot_analysis.get('bots', []):
            if bot['severity'] == 'high' and bot['type'] not in ['Search Engine', 'Social Media']:
                self.threats.append({
                    'id': len(self.threats) + 1,
                    'timestamp': datetime.now().isoformat(),
                    'type': 'malicious_bot',
                    'severity': bot['severity'],
                    'details': bot,
                    'resolved': False
                })

        # 3. Detectar ataques de fuerza bruta
        brute_force = self.log_analyzer.detect_brute_force()
        for attack in brute_force:
            self.threats.append({
                'id': len(self.threats) + 1,
                'timestamp': datetime.now().isoformat(),
                'type': 'brute_force_attack',
                'severity': 'high' if attack['attempts'] > 50 else 'medium',
                'details': attack,
                'resolved': False
            })

        # 4. Detectar escaneo de vulnerabilidades
        self._detect_vulnerability_scans()

        # 5. Detectar intentos de SQL injection
        self._detect_sql_injection()

        # 6. Detectar intentos de XSS
        self._detect_xss_attempts()

        return {
            'success': True,
            'threats_found': len(self.threats),
            'threats': self.threats
        }

    def _detect_vulnerability_scans(self):
        """Detectar escaneos de vulnerabilidades"""
        nginx_logs = self.log_analyzer.get_nginx_logs(limit=5000)

        vuln_patterns = {
            'wordpress_scan': ['/wp-admin', '/wp-login', '/wp-content'],
            'phpmyadmin_scan': ['/phpmyadmin', '/pma', '/phpMyAdmin'],
            'config_file_access': ['/.env', '/config.php', '/configuration.php', '/.git'],
            'admin_panel_scan': ['/admin', '/administrator', '/panel', '/cpanel'],
            'backup_file_scan': ['.zip', '.tar', '.sql', '.backup', '.bak'],
        }

        ip_vuln_attempts = {}

        for log in nginx_logs:
            ip = log.get('ip')
            path = log.get('path', '')

            for vuln_type, patterns in vuln_patterns.items():
                for pattern in patterns:
                    if pattern in path.lower():
                        if ip not in ip_vuln_attempts:
                            ip_vuln_attempts[ip] = {'types': set(), 'count': 0}

                        ip_vuln_attempts[ip]['types'].add(vuln_type)
                        ip_vuln_attempts[ip]['count'] += 1

        # Generar amenazas
        for ip, data in ip_vuln_attempts.items():
            if data['count'] >= 5 or len(data['types']) >= 3:
                self.threats.append({
                    'id': len(self.threats) + 1,
                    'timestamp': datetime.now().isoformat(),
                    'type': 'vulnerability_scan',
                    'severity': 'high' if len(data['types']) >= 3 else 'medium',
                    'details': {
                        'ip': ip,
                        'scan_types': list(data['types']),
                        'attempt_count': data['count']
                    },
                    'resolved': False
                })

    def _detect_sql_injection(self):
        """Detectar intentos de SQL injection"""
        nginx_logs = self.log_analyzer.get_nginx_logs(limit=5000)

        sql_patterns = [
            r"union.*select",
            r"select.*from",
            r"insert.*into",
            r"delete.*from",
            r"drop.*table",
            r"' or '1'='1",
            r"' or 1=1",
            r"admin'--",
            r"' union ",
        ]

        sql_attempts = {}

        for log in nginx_logs:
            ip = log.get('ip')
            path = log.get('path', '')

            for pattern in sql_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    if ip not in sql_attempts:
                        sql_attempts[ip] = []
                    sql_attempts[ip].append({
                        'path': path,
                        'pattern': pattern
                    })

        for ip, attempts in sql_attempts.items():
            if len(attempts) >= 1:
                self.threats.append({
                    'id': len(self.threats) + 1,
                    'timestamp': datetime.now().isoformat(),
                    'type': 'sql_injection_attempt',
                    'severity': 'high',
                    'details': {
                        'ip': ip,
                        'attempts': len(attempts),
                        'examples': attempts[:5]
                    },
                    'resolved': False
                })

    def _detect_xss_attempts(self):
        """Detectar intentos de XSS"""
        nginx_logs = self.log_analyzer.get_nginx_logs(limit=5000)

        xss_patterns = [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"eval\(",
            r"alert\(",
        ]

        xss_attempts = {}

        for log in nginx_logs:
            ip = log.get('ip')
            path = log.get('path', '')

            for pattern in xss_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    if ip not in xss_attempts:
                        xss_attempts[ip] = []
                    xss_attempts[ip].append({
                        'path': path,
                        'pattern': pattern
                    })

        for ip, attempts in xss_attempts.items():
            if len(attempts) >= 1:
                self.threats.append({
                    'id': len(self.threats) + 1,
                    'timestamp': datetime.now().isoformat(),
                    'type': 'xss_attempt',
                    'severity': 'high',
                    'details': {
                        'ip': ip,
                        'attempts': len(attempts),
                        'examples': attempts[:5]
                    },
                    'resolved': False
                })

    def get_all_threats(self):
        """Obtener todas las amenazas"""
        return self.threats

    def get_active_threats_count(self):
        """Obtener cantidad de amenazas activas"""
        return len([t for t in self.threats if not t.get('resolved', False)])

    def get_recent_threats(self, limit=10):
        """Obtener amenazas recientes"""
        sorted_threats = sorted(
            self.threats,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )
        return sorted_threats[:limit]

    def resolve_threat(self, threat_id):
        """Marcar amenaza como resuelta"""
        for threat in self.threats:
            if threat['id'] == threat_id:
                threat['resolved'] = True
                threat['resolved_at'] = datetime.now().isoformat()
                return {'success': True, 'message': 'Threat resolved'}

        return {'success': False, 'error': 'Threat not found'}

    def get_threats_by_type(self, threat_type):
        """Obtener amenazas por tipo"""
        return [t for t in self.threats if t['type'] == threat_type]

    def get_threats_by_severity(self, severity):
        """Obtener amenazas por severidad"""
        return [t for t in self.threats if t['severity'] == severity]

    def get_threat_statistics(self):
        """Obtener estadísticas de amenazas"""
        total = len(self.threats)
        active = len([t for t in self.threats if not t.get('resolved', False)])
        resolved = total - active

        by_type = {}
        by_severity = {}

        for threat in self.threats:
            threat_type = threat['type']
            severity = threat['severity']

            by_type[threat_type] = by_type.get(threat_type, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            'total': total,
            'active': active,
            'resolved': resolved,
            'by_type': by_type,
            'by_severity': by_severity
        }
