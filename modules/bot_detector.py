"""
Detector de Bots y Scrapers
"""
import re
from collections import Counter
from .log_analyzer import LogAnalyzer


class BotDetector:
    def __init__(self):
        self.log_analyzer = LogAnalyzer()
        self.detected_bots = []

        # User agents conocidos de bots
        self.known_bot_patterns = [
            r'bot',
            r'crawler',
            r'spider',
            r'scraper',
            r'curl',
            r'wget',
            r'python-requests',
            r'axios',
            r'java',
            r'go-http-client',
            r'scrapy',
            r'headless',
        ]

        # Patrones de comportamiento sospechoso
        self.suspicious_patterns = {
            'rapid_requests': 100,  # Más de 100 peticiones
            'no_referrer_threshold': 0.8,  # 80% sin referrer
            'path_depth_threshold': 5,  # Profundidad de rutas
        }

    def analyze_logs(self):
        """Analizar logs en busca de bots"""
        nginx_logs = self.log_analyzer.get_nginx_logs(limit=5000)

        # Agrupar por IP
        ip_data = {}
        for log in nginx_logs:
            ip = log.get('ip')
            if not ip:
                continue

            if ip not in ip_data:
                ip_data[ip] = {
                    'requests': [],
                    'user_agents': [],
                    'paths': [],
                    'referrers': []
                }

            ip_data[ip]['requests'].append(log)
            ip_data[ip]['user_agents'].append(log.get('user_agent', ''))
            ip_data[ip]['paths'].append(log.get('path', ''))
            ip_data[ip]['referrers'].append(log.get('referrer', ''))

        # Analizar cada IP
        detected_bots = []
        for ip, data in ip_data.items():
            bot_score = 0
            reasons = []

            # 1. Verificar user agent
            user_agents = data['user_agents']
            for ua in user_agents:
                for pattern in self.known_bot_patterns:
                    if re.search(pattern, ua, re.IGNORECASE):
                        bot_score += 30
                        reasons.append(f'Bot user agent detected: {pattern}')
                        break

            # 2. Velocidad de peticiones
            request_count = len(data['requests'])
            if request_count > self.suspicious_patterns['rapid_requests']:
                bot_score += 25
                reasons.append(f'Rapid requests: {request_count}')

            # 3. Sin referrer
            no_referrer = sum(1 for r in data['referrers'] if r == '-' or not r)
            if request_count > 0:
                no_referrer_ratio = no_referrer / request_count
                if no_referrer_ratio > self.suspicious_patterns['no_referrer_threshold']:
                    bot_score += 20
                    reasons.append(f'High no-referrer ratio: {no_referrer_ratio:.2%}')

            # 4. Patrones de rutas sospechosos
            paths = data['paths']
            unique_paths = len(set(paths))

            # Buscar patrones secuenciales (ej: /page/1, /page/2, /page/3)
            sequential_pattern = re.compile(r'/\d+')
            sequential_paths = [p for p in paths if sequential_pattern.search(p)]
            if len(sequential_paths) > 20:
                bot_score += 15
                reasons.append(f'Sequential path access: {len(sequential_paths)}')

            # 5. Diversidad de user agents (bots suelen usar el mismo)
            unique_user_agents = len(set(user_agents))
            if unique_user_agents == 1 and request_count > 10:
                bot_score += 10
                reasons.append('Single user agent for multiple requests')

            # 6. Buscar acceso a archivos específicos
            suspicious_files = ['.xml', 'sitemap', 'robots.txt', '.json', '/api/']
            for path in paths:
                for sus_file in suspicious_files:
                    if sus_file in path.lower():
                        bot_score += 5
                        reasons.append(f'Accessed: {sus_file}')
                        break

            # Clasificar como bot si el score es alto
            if bot_score >= 30:
                bot_type = self._classify_bot_type(data, reasons)
                detected_bots.append({
                    'ip': ip,
                    'score': bot_score,
                    'reasons': reasons,
                    'type': bot_type,
                    'request_count': request_count,
                    'user_agent': user_agents[0] if user_agents else 'Unknown',
                    'severity': 'high' if bot_score >= 60 else 'medium'
                })

        self.detected_bots = detected_bots
        return {
            'success': True,
            'detected_count': len(detected_bots),
            'bots': detected_bots
        }

    def _classify_bot_type(self, data, reasons):
        """Clasificar tipo de bot"""
        user_agent = data['user_agents'][0] if data['user_agents'] else ''

        # Bots legítimos
        legitimate_bots = {
            'googlebot': 'Search Engine (Google)',
            'bingbot': 'Search Engine (Bing)',
            'yandex': 'Search Engine (Yandex)',
            'duckduckbot': 'Search Engine (DuckDuckGo)',
            'baiduspider': 'Search Engine (Baidu)',
            'facebookexternalhit': 'Social Media (Facebook)',
            'twitterbot': 'Social Media (Twitter)',
            'linkedinbot': 'Social Media (LinkedIn)',
        }

        for bot_name, bot_type in legitimate_bots.items():
            if bot_name in user_agent.lower():
                return bot_type

        # Scrapers conocidos
        if any(x in user_agent.lower() for x in ['scrapy', 'beautifulsoup', 'selenium']):
            return 'Web Scraper'

        # Herramientas de línea de comandos
        if any(x in user_agent.lower() for x in ['curl', 'wget', 'python-requests', 'axios']):
            return 'HTTP Client Tool'

        # Por comportamiento
        if 'Rapid requests' in str(reasons):
            return 'Aggressive Scraper'

        return 'Unknown Bot'

    def get_detected_bots(self):
        """Obtener bots detectados"""
        return self.detected_bots

    def get_detected_bots_count(self):
        """Obtener cantidad de bots detectados"""
        return len(self.detected_bots)

    def is_legitimate_bot(self, user_agent):
        """Verificar si es un bot legítimo"""
        legitimate_bots = [
            'googlebot',
            'bingbot',
            'yandex',
            'duckduckbot',
            'baiduspider',
            'facebookexternalhit',
            'twitterbot',
            'linkedinbot',
            'slackbot',
            'telegrambot'
        ]

        ua_lower = user_agent.lower()
        return any(bot in ua_lower for bot in legitimate_bots)

    def block_bot(self, ip):
        """Bloquear bot usando fail2ban"""
        from .fail2ban_manager import Fail2banManager
        fail2ban = Fail2banManager()

        # Crear jail personalizada para bots si no existe
        jail_name = 'http-bot-blocker'

        # Bloquear IP
        result = fail2ban.ban_ip(ip, jail_name)
        return result

    def analyze_user_agent(self, user_agent):
        """Analizar un user agent específico"""
        score = 0
        flags = []

        # Verificar patrones de bot
        for pattern in self.known_bot_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                score += 20
                flags.append(f'Contains bot pattern: {pattern}')

        # Verificar si es muy corto (bots suelen tener UA cortos)
        if len(user_agent) < 20:
            score += 10
            flags.append('Very short user agent')

        # Verificar si falta información común
        if 'Mozilla' not in user_agent and 'Chrome' not in user_agent and 'Safari' not in user_agent:
            score += 15
            flags.append('Missing common browser identifiers')

        is_bot = score >= 20
        is_legitimate = self.is_legitimate_bot(user_agent)

        return {
            'is_bot': is_bot,
            'is_legitimate': is_legitimate,
            'score': score,
            'flags': flags,
            'user_agent': user_agent
        }
