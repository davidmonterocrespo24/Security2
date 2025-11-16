"""
Sistema de Detección de Ataques Avanzado
Detecta múltiples tipos de ataques en tiempo real
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict
import json


class AttackDetector:
    def __init__(self, db_manager):
        self.db = db_manager
        self.attack_cache = defaultdict(list)  # Cache de ataques por IP

        # Patrones de ataque
        self.sql_injection_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec(\s|\+)+(s|x)p\w+",
            r"UNION.*SELECT",
            r"SELECT.*FROM.*WHERE",
            r"INSERT.*INTO.*VALUES",
            r"DELETE.*FROM.*WHERE",
            r"DROP.*TABLE",
            r"UPDATE.*SET.*WHERE",
        ]

        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe",
            r"<object",
            r"<embed",
            r"eval\(",
            r"expression\(",
        ]

        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\%2[fF]",
            r"%2e%2e/",
            r"\.\.\\",
            r"/etc/passwd",
            r"/etc/shadow",
            r"C:\\Windows",
            r"C:\\boot\.ini",
        ]

        self.command_injection_patterns = [
            r";.*?(ls|cat|wget|curl|nc|netcat|bash|sh)",
            r"\|.*?(ls|cat|wget|curl|nc|netcat|bash|sh)",
            r"&&.*?(ls|cat|wget|curl|nc|netcat|bash|sh)",
            r"`.*?`",
            r"\$\(.*?\)",
        ]

        # Patrones de bots maliciosos
        self.malicious_bot_patterns = [
            r"nikto",
            r"sqlmap",
            r"nmap",
            r"masscan",
            r"metasploit",
            r"havij",
            r"acunetix",
            r"nessus",
            r"openvas",
            r"w3af",
            r"dirbuster",
            r"gobuster",
            r"wpscan",
            r"skipfish",
            r"burp",
        ]

        # User agents sospechosos
        self.suspicious_user_agents = [
            "python-requests",
            "curl",
            "wget",
            "scrapy",
            "bot",
            "crawler",
            "spider",
            "scraper",
        ]

    def detect_sql_injection(self, input_string):
        """Detectar intentos de SQL injection"""
        if not input_string:
            return False, None

        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True, f"SQL Injection pattern detected: {pattern[:50]}"

        return False, None

    def detect_xss(self, input_string):
        """Detectar intentos de XSS"""
        if not input_string:
            return False, None

        for pattern in self.xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True, f"XSS pattern detected: {pattern[:50]}"

        return False, None

    def detect_path_traversal(self, input_string):
        """Detectar path traversal"""
        if not input_string:
            return False, None

        for pattern in self.path_traversal_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True, f"Path traversal detected: {pattern[:50]}"

        return False, None

    def detect_command_injection(self, input_string):
        """Detectar command injection"""
        if not input_string:
            return False, None

        for pattern in self.command_injection_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True, f"Command injection detected: {pattern[:50]}"

        return False, None

    def detect_malicious_bot(self, user_agent):
        """Detectar bots maliciosos por User-Agent"""
        if not user_agent:
            return False, None

        user_agent_lower = user_agent.lower()

        # Verificar herramientas de hacking
        for pattern in self.malicious_bot_patterns:
            if pattern in user_agent_lower:
                return True, f"Malicious tool detected: {pattern}"

        # Verificar user agents sospechosos
        for agent in self.suspicious_user_agents:
            if agent in user_agent_lower:
                # Verificar si NO es un bot legítimo (Google, Bing, etc.)
                if not any(legitimate in user_agent_lower for legitimate in ['googlebot', 'bingbot', 'yandex', 'baidu']):
                    return True, f"Suspicious user agent: {agent}"

        return False, None

    def detect_ssh_brute_force(self, ip_address, failed_attempts=5, time_window=600):
        """Detectar ataques de fuerza bruta SSH"""
        # Obtener eventos SSH recientes de esta IP
        events = self.db.get_events_by_ip(ip_address, limit=100)

        ssh_failures = [e for e in events if e.get('event_type') == 'ssh_failed_login']

        # Contar fallos en la ventana de tiempo
        cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)
        recent_failures = [
            e for e in ssh_failures
            if datetime.fromisoformat(e['timestamp']) > cutoff_time
        ]

        if len(recent_failures) >= failed_attempts:
            return True, f"SSH brute force: {len(recent_failures)} failed attempts in {time_window}s"

        return False, None

    def detect_http_flooding(self, ip_address, max_requests=100, time_window=60):
        """Detectar flooding HTTP (DDoS)"""
        # Obtener eventos HTTP recientes de esta IP
        events = self.db.get_events_by_ip(ip_address, limit=200)

        http_requests = [e for e in events if e.get('protocol') in ['http', 'https']]

        # Contar peticiones en la ventana de tiempo
        cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)
        recent_requests = [
            e for e in http_requests
            if datetime.fromisoformat(e['timestamp']) > cutoff_time
        ]

        if len(recent_requests) >= max_requests:
            return True, f"HTTP flooding: {len(recent_requests)} requests in {time_window}s"

        return False, None

    def detect_port_scan(self, ip_address, unique_ports_threshold=10, time_window=60):
        """Detectar escaneo de puertos"""
        events = self.db.get_events_by_ip(ip_address, limit=200)

        cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)
        recent_events = [
            e for e in events
            if datetime.fromisoformat(e['timestamp']) > cutoff_time and e.get('target_port')
        ]

        unique_ports = set(e['target_port'] for e in recent_events)

        if len(unique_ports) >= unique_ports_threshold:
            return True, f"Port scan detected: {len(unique_ports)} unique ports in {time_window}s"

        return False, None

    def analyze_http_request(self, ip_address, method, path, user_agent, headers=None, body=None):
        """Análisis completo de una petición HTTP"""
        threats = []
        severity = 'low'

        # Detectar SQL injection en path
        is_sqli, sqli_detail = self.detect_sql_injection(path)
        if is_sqli:
            threats.append({
                'type': 'sql_injection',
                'severity': 'high',
                'detail': sqli_detail,
                'location': 'path'
            })
            severity = 'high'

        # Detectar XSS en path
        is_xss, xss_detail = self.detect_xss(path)
        if is_xss:
            threats.append({
                'type': 'xss',
                'severity': 'high',
                'detail': xss_detail,
                'location': 'path'
            })
            severity = 'high'

        # Detectar path traversal
        is_traversal, traversal_detail = self.detect_path_traversal(path)
        if is_traversal:
            threats.append({
                'type': 'path_traversal',
                'severity': 'high',
                'detail': traversal_detail,
                'location': 'path'
            })
            severity = 'high'

        # Detectar command injection
        is_cmd_inj, cmd_detail = self.detect_command_injection(path)
        if is_cmd_inj:
            threats.append({
                'type': 'command_injection',
                'severity': 'critical',
                'detail': cmd_detail,
                'location': 'path'
            })
            severity = 'critical'

        # Detectar bot malicioso
        is_bot, bot_detail = self.detect_malicious_bot(user_agent)
        if is_bot:
            threats.append({
                'type': 'malicious_bot',
                'severity': 'medium',
                'detail': bot_detail,
                'location': 'user_agent'
            })
            if severity == 'low':
                severity = 'medium'

        # Detectar flooding
        is_flooding, flood_detail = self.detect_http_flooding(ip_address)
        if is_flooding:
            threats.append({
                'type': 'http_flooding',
                'severity': 'high',
                'detail': flood_detail,
                'location': 'rate'
            })
            if severity not in ['critical']:
                severity = 'high'

        # Si hay amenazas, registrar evento
        if threats:
            threat_types = [t['type'] for t in threats]
            details = json.dumps(threats)

            event_id = self.db.log_security_event(
                event_type='http_attack',
                severity=severity,
                source_ip=ip_address,
                protocol='http',
                request_path=path,
                user_agent=user_agent,
                attack_vector=','.join(threat_types),
                details=details
            )

            return {
                'is_threat': True,
                'severity': severity,
                'threats': threats,
                'event_id': event_id,
                'should_block': severity in ['high', 'critical']
            }

        return {
            'is_threat': False,
            'severity': 'none',
            'threats': [],
            'should_block': False
        }

    def analyze_ssh_attempt(self, ip_address, username, success, auth_method='password'):
        """Analizar intento de login SSH"""
        event_type = 'ssh_successful_login' if success else 'ssh_failed_login'
        severity = 'low' if success else 'medium'

        # Registrar evento
        event_id = self.db.log_security_event(
            event_type=event_type,
            severity=severity,
            source_ip=ip_address,
            protocol='ssh',
            details=json.dumps({
                'username': username,
                'auth_method': auth_method,
                'success': success
            })
        )

        # Si falló, verificar brute force
        if not success:
            is_bruteforce, bf_detail = self.detect_ssh_brute_force(ip_address)

            if is_bruteforce:
                # Actualizar evento con detección de brute force
                self.db.log_security_event(
                    event_type='ssh_brute_force',
                    severity='high',
                    source_ip=ip_address,
                    protocol='ssh',
                    attack_vector='brute_force',
                    details=bf_detail
                )

                return {
                    'is_threat': True,
                    'threat_type': 'ssh_brute_force',
                    'severity': 'high',
                    'detail': bf_detail,
                    'should_block': True
                }

        return {
            'is_threat': False,
            'should_block': False
        }

    def get_threat_score(self, ip_address):
        """Calcular score de amenaza para una IP (0-100)"""
        events = self.db.get_events_by_ip(ip_address, limit=100)

        if not events:
            return 0

        score = 0

        # Contar por tipo de ataque
        for event in events:
            event_type = event.get('event_type', '')
            severity = event.get('severity', 'low')

            # Puntos base por tipo
            if 'brute_force' in event_type:
                score += 10
            elif 'injection' in event_type:
                score += 15
            elif 'flooding' in event_type:
                score += 8
            elif 'scan' in event_type:
                score += 5
            elif 'bot' in event_type:
                score += 3

            # Multiplicador por severidad
            if severity == 'critical':
                score += 20
            elif severity == 'high':
                score += 10
            elif severity == 'medium':
                score += 5

        # Cap at 100
        return min(score, 100)

    def should_auto_block(self, ip_address, current_threat_severity='low'):
        """Determinar si se debe bloquear automáticamente una IP"""
        # Verificar whitelist
        if self.db.is_ip_whitelisted(ip_address):
            return False, "IP is whitelisted"

        # Verificar blacklist
        if self.db.is_ip_blacklisted(ip_address):
            return True, "IP is blacklisted"

        # Obtener configuración
        auto_block_threshold = self.db.get_config('auto_block_threshold') or 10

        # Calcular score
        threat_score = self.get_threat_score(ip_address)

        # Decidir basado en score y severidad actual
        if current_threat_severity == 'critical':
            return True, f"Critical threat detected (score: {threat_score})"

        if current_threat_severity == 'high' and threat_score >= auto_block_threshold:
            return True, f"High threat with score {threat_score} >= threshold {auto_block_threshold}"

        if threat_score >= auto_block_threshold * 2:
            return True, f"Threat score {threat_score} exceeds auto-block threshold"

        return False, f"Below threshold (score: {threat_score}, threshold: {auto_block_threshold})"

    def generate_alert(self, alert_type, severity, title, message, source=None):
        """Generar alerta en el sistema"""
        alert_id = self.db.create_alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            source=source
        )

        return alert_id
