"""
Gestor de Fail2ban
"""
import subprocess
import re
import os
from datetime import datetime


class Fail2banManager:
    def __init__(self, db_manager=None):
        self.fail2ban_available = self._check_fail2ban_available()
        self.fail2ban_client = 'fail2ban-client'

        # Inicializar sistema de alertas
        self.alert_manager = None
        if db_manager:
            try:
                from modules.alert_manager import AlertManager
                self.alert_manager = AlertManager(db_manager)
            except Exception as e:
                print(f"Advertencia: No se pudo inicializar AlertManager: {e}")

    def _check_fail2ban_available(self):
        """Verificar si Fail2ban está disponible"""
        # Intentar múltiples métodos de detección
        try:
            # Método 1: which
            result = subprocess.run(['which', 'fail2ban-client'], capture_output=True, text=True)
            if result.returncode == 0:
                return True
        except:
            pass

        try:
            # Método 2: verificar rutas comunes
            common_paths = [
                '/usr/bin/fail2ban-client',
                '/usr/local/bin/fail2ban-client',
                '/bin/fail2ban-client'
            ]
            for path in common_paths:
                if os.path.exists(path):
                    self.fail2ban_client = path
                    return True
        except:
            pass

        try:
            # Método 3: intentar ejecutar directamente
            result = subprocess.run(['fail2ban-client', '--version'],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return True
        except:
            pass

        try:
            # Método 4: verificar con systemctl
            result = subprocess.run(['systemctl', 'is-active', 'fail2ban'],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                # Si el servicio está activo, fail2ban está instalado
                self.fail2ban_client = '/usr/bin/fail2ban-client'
                return True
        except:
            pass

        return False

    def _run_command(self, command):
        """Ejecutar comando del sistema"""
        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            return {
                'success': result.returncode == 0,
                'output': result.stdout.strip(),
                'error': result.stderr.strip()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_status(self):
        """Obtener estado de Fail2ban"""
        if not self.fail2ban_available:
            return {
                'running': False,
                'available': False,
                'message': 'Fail2ban no está instalado'
            }

        result = self._run_command('sudo systemctl is-active fail2ban')
        running = result['output'] == 'active'

        return {
            'running': running,
            'available': True,
            'status': result['output']
        }

    def get_jails(self):
        """Obtener lista de jails configuradas"""
        if not self.fail2ban_available:
            return []

        result = self._run_command(f'sudo {self.fail2ban_client} status')
        if not result['success']:
            return []

        # Parsear output para obtener lista de jails
        jails = []
        output = result['output']

        # Buscar línea con "Jail list:"
        for line in output.split('\n'):
            if 'Jail list:' in line:
                # Extraer nombres de jails
                jail_list = line.split('Jail list:')[1].strip()
                jail_names = [j.strip() for j in jail_list.split(',')]

                # Obtener información detallada de cada jail
                for jail_name in jail_names:
                    jail_info = self.get_jail_info(jail_name)
                    if jail_info:
                        jails.append(jail_info)

        return jails

    def get_jail_info(self, jail_name):
        """Obtener información de una jail específica"""
        if not self.fail2ban_available:
            return None

        result = self._run_command(f'sudo {self.fail2ban_client} status {jail_name}')
        if not result['success']:
            return None

        info = {
            'name': jail_name,
            'enabled': True,
            'banned_count': 0,
            'banned_ips': [],
            'total_failed': 0,
            'total_banned': 0
        }

        # Parsear output
        for line in result['output'].split('\n'):
            if 'Currently banned:' in line:
                info['banned_count'] = int(line.split(':')[1].strip())
            elif 'Total banned:' in line:
                info['total_banned'] = int(line.split(':')[1].strip())
            elif 'Currently failed:' in line or 'Total failed:' in line:
                try:
                    info['total_failed'] = int(line.split(':')[1].strip())
                except:
                    pass
            elif 'Banned IP list:' in line:
                ips = line.split(':')[1].strip()
                if ips:
                    info['banned_ips'] = ips.split()

        return info

    def get_banned_ips(self, jail='sshd'):
        """Obtener IPs bloqueadas en una jail"""
        if not self.fail2ban_available:
            return []

        jail_info = self.get_jail_info(jail)
        if jail_info:
            return jail_info.get('banned_ips', [])
        return []

    def get_blocked_ips_count(self):
        """Obtener cantidad total de IPs bloqueadas"""
        jails = self.get_jails()
        total = sum(jail.get('banned_count', 0) for jail in jails)
        return total

    def get_recent_blocks(self, limit=10):
        """Obtener bloqueos recientes"""
        if not self.fail2ban_available:
            return []

        # Leer log de fail2ban
        log_file = '/var/log/fail2ban.log'
        if not os.path.exists(log_file):
            return []

        try:
            result = self._run_command(f'sudo tail -n 1000 {log_file} | grep "Ban"')
            if not result['success']:
                return []

            blocks = []
            lines = result['output'].split('\n')[-limit:]

            for line in lines:
                # Parsear línea de log
                match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*\[(\w+)\] Ban (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    blocks.append({
                        'timestamp': match.group(1),
                        'jail': match.group(2),
                        'ip': match.group(3)
                    })

            return blocks
        except Exception as e:
            print(f"Error reading fail2ban log: {e}")
            return []

    def ban_ip(self, ip, jail='sshd'):
        """Bloquear IP manualmente"""
        if not self.fail2ban_available:
            return {'success': False, 'error': 'Fail2ban no disponible'}

        command = f'sudo {self.fail2ban_client} set {jail} banip {ip}'
        result = self._run_command(command)

        # DISPARAR ALERTA si el ban fue exitoso
        if result['success'] and self.alert_manager:
            try:
                self.alert_manager.process_alert({
                    'type': 'fail2ban_action',
                    'action': 'manual_ban',
                    'severity': 'HIGH',
                    'ip': ip,
                    'jail': jail,
                    'reason': f"IP {ip} bloqueada manualmente en jail {jail}",
                    'timestamp': datetime.utcnow().isoformat()
                })
            except Exception as e:
                print(f"Error disparando alerta de Fail2ban ban: {e}")

        return result

    def unban_ip(self, ip, jail='sshd'):
        """Desbloquear IP"""
        if not self.fail2ban_available:
            return {'success': False, 'error': 'Fail2ban no disponible'}

        command = f'sudo {self.fail2ban_client} set {jail} unbanip {ip}'
        result = self._run_command(command)
        return result

    def toggle_jail(self, jail, enable=True):
        """Activar/desactivar jail"""
        if not self.fail2ban_available:
            return {'success': False, 'error': 'Fail2ban no disponible'}

        action = 'start' if enable else 'stop'
        command = f'sudo {self.fail2ban_client} {action} {jail}'
        result = self._run_command(command)
        return result

    def reload_config(self):
        """Recargar configuración de Fail2ban"""
        if not self.fail2ban_available:
            return {'success': False, 'error': 'Fail2ban no disponible'}

        command = f'sudo {self.fail2ban_client} reload'
        result = self._run_command(command)
        return result

    def update_jail_config(self, jail, config):
        """Actualizar configuración de jail"""
        if not self.fail2ban_available:
            return {'success': False, 'error': 'Fail2ban no disponible'}

        # Crear archivo de configuración local
        config_path = f'/etc/fail2ban/jail.d/{jail}.local'

        config_content = f"""[{jail}]
enabled = {str(config.get('enabled', True)).lower()}
maxretry = {config.get('maxretry', 5)}
findtime = {config.get('findtime', 600)}
bantime = {config.get('bantime', 3600)}
"""

        if 'port' in config:
            config_content += f"port = {config['port']}\n"

        if 'logpath' in config:
            config_content += f"logpath = {config['logpath']}\n"

        # Guardar configuración
        try:
            with open('/tmp/jail_config.tmp', 'w') as f:
                f.write(config_content)

            self._run_command(f'sudo mv /tmp/jail_config.tmp {config_path}')
            self.reload_config()

            return {'success': True, 'message': 'Configuración actualizada'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_custom_jail(self, name, config):
        """Crear jail personalizada"""
        jail_config = {
            'enabled': True,
            'maxretry': config.get('maxretry', 5),
            'findtime': config.get('findtime', 600),
            'bantime': config.get('bantime', 3600),
            'port': config.get('port', 'http,https'),
            'logpath': config.get('logpath', '/var/log/nginx/access.log')
        }

        if 'filter' in config:
            jail_config['filter'] = config['filter']

        return self.update_jail_config(name, jail_config)

    def get_available_filters(self):
        """Obtener lista de filtros disponibles"""
        if not self.fail2ban_available:
            return []

        try:
            result = self._run_command('ls /etc/fail2ban/filter.d/*.conf')
            if result['success']:
                filters = []
                for line in result['output'].split('\n'):
                    if line:
                        filter_name = os.path.basename(line).replace('.conf', '')
                        filters.append(filter_name)
                return sorted(filters)
        except:
            pass
        return []

    def create_nginx_rate_limit_jail(self, maxretry=100, findtime=60, bantime=3600, logpath='/var/log/nginx/access.log'):
        """Crear jail para limitar peticiones HTTP desde el panel web"""
        if not self.fail2ban_available:
            return {'success': False, 'error': 'Fail2ban no disponible'}

        try:
            # 1. Crear filtro agresivo si no existe
            filter_path = '/etc/fail2ban/filter.d/nginx-req-limit-aggressive.conf'
            filter_content = """# Fail2ban filter para bloquear ataques DDoS/flooding
# Creado desde el panel web

[Definition]
failregex = ^<HOST> -.*"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS).*HTTP.*"
ignoreregex =

[Init]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
"""

            # Escribir filtro en /tmp y moverlo
            with open('/tmp/nginx-req-limit-aggressive.conf', 'w') as f:
                f.write(filter_content)

            result = self._run_command(f'sudo mv /tmp/nginx-req-limit-aggressive.conf {filter_path}')
            if not result['success']:
                return {'success': False, 'error': 'No se pudo crear el filtro'}

            # 2. Crear jail
            jail_path = '/etc/fail2ban/jail.d/nginx-req-limit.local'
            jail_content = f"""# Jail para bloquear IPs con demasiadas peticiones HTTP
# Creado desde el panel web

[nginx-req-limit]
enabled = true
port = http,https
filter = nginx-req-limit-aggressive
logpath = {logpath}
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = %(action_mwl)s
"""

            with open('/tmp/nginx-req-limit.local', 'w') as f:
                f.write(jail_content)

            result = self._run_command(f'sudo mv /tmp/nginx-req-limit.local {jail_path}')
            if not result['success']:
                return {'success': False, 'error': 'No se pudo crear la jail'}

            # 3. Reiniciar fail2ban
            restart_result = self._run_command('sudo systemctl restart fail2ban')
            if not restart_result['success']:
                return {'success': False, 'error': 'No se pudo reiniciar fail2ban'}

            return {
                'success': True,
                'message': f'Jail nginx-req-limit creada exitosamente. Bloqueará IPs que hagan más de {maxretry} peticiones en {findtime} segundos.',
                'config': {
                    'maxretry': maxretry,
                    'findtime': findtime,
                    'bantime': bantime,
                    'logpath': logpath
                }
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_bot_blocker_jail(self, maxretry=50, findtime=300, bantime=7200, logpath='/var/log/nginx/access.log'):
        """Crear jail para bloquear bots maliciosos desde el panel web"""
        if not self.fail2ban_available:
            return {'success': False, 'error': 'Fail2ban no disponible'}

        try:
            # 1. Crear filtro para bots
            filter_path = '/etc/fail2ban/filter.d/http-bot-blocker.conf'
            filter_content = """# Fail2ban filter para bloquear bots maliciosos
# Creado desde el panel web

[Definition]
failregex = ^<HOST> -.*"(GET|POST).*".*"(bot|crawler|spider|scraper|curl|wget|python-requests|axios|nikto|sqlmap|nmap).*"
ignoreregex = (Googlebot|bingbot|YandexBot|Baiduspider)
"""

            with open('/tmp/http-bot-blocker.conf', 'w') as f:
                f.write(filter_content)

            result = self._run_command(f'sudo mv /tmp/http-bot-blocker.conf {filter_path}')
            if not result['success']:
                return {'success': False, 'error': 'No se pudo crear el filtro de bots'}

            # 2. Crear jail
            jail_path = '/etc/fail2ban/jail.d/http-bot-blocker.local'
            jail_content = f"""# Jail para bloquear bots maliciosos
# Creado desde el panel web

[http-bot-blocker]
enabled = true
port = http,https
filter = http-bot-blocker
logpath = {logpath}
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = %(action_mwl)s
"""

            with open('/tmp/http-bot-blocker.local', 'w') as f:
                f.write(jail_content)

            result = self._run_command(f'sudo mv /tmp/http-bot-blocker.local {jail_path}')
            if not result['success']:
                return {'success': False, 'error': 'No se pudo crear la jail de bots'}

            # 3. Reiniciar fail2ban
            restart_result = self._run_command('sudo systemctl restart fail2ban')
            if not restart_result['success']:
                return {'success': False, 'error': 'No se pudo reiniciar fail2ban'}

            return {
                'success': True,
                'message': f'Jail http-bot-blocker creada exitosamente. Bloqueará bots maliciosos.',
                'config': {
                    'maxretry': maxretry,
                    'findtime': findtime,
                    'bantime': bantime,
                    'logpath': logpath
                }
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_jail_config(self, jail_name):
        """Obtener configuración actual de una jail"""
        if not self.fail2ban_available:
            return None

        jail_file = f'/etc/fail2ban/jail.d/{jail_name}.local'

        try:
            result = self._run_command(f'sudo cat {jail_file}')
            if result['success']:
                config = {}
                for line in result['output'].split('\n'):
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
                return config
        except:
            pass

        return None

    def monitor_and_alert_bans(self, limit=50):
        """
        Monitorear bloqueos recientes de Fail2ban y disparar alertas
        Esta función se puede ejecutar periódicamente desde el task scheduler

        Args:
            limit: Número de bloqueos recientes a revisar

        Returns:
            dict: Resumen de alertas disparadas
        """
        if not self.alert_manager:
            return {'success': False, 'message': 'AlertManager no inicializado'}

        blocks = self.get_recent_blocks(limit=limit)
        alerts_sent = 0

        # Mantener registro de IPs ya alertadas para evitar spam
        # (en producción esto debería usar una base de datos o caché)
        alerted_ips = set()

        for block in blocks:
            ip = block['ip']
            jail = block['jail']

            # Evitar alertas duplicadas en la misma ejecución
            if ip in alerted_ips:
                continue

            # Determinar severidad según jail
            severity = 'MEDIUM'
            if jail in ['sshd', 'ssh']:
                severity = 'HIGH'
            elif 'nginx' in jail or 'http' in jail:
                severity = 'MEDIUM'

            # Disparar alerta
            try:
                self.alert_manager.process_alert({
                    'type': 'fail2ban_ban',
                    'severity': severity,
                    'ip': ip,
                    'jail': jail,
                    'timestamp': block.get('timestamp', datetime.utcnow().isoformat()),
                    'reason': f"IP {ip} bloqueada por Fail2ban en jail {jail}"
                })
                alerts_sent += 1
                alerted_ips.add(ip)
            except Exception as e:
                print(f"Error disparando alerta de Fail2ban para {ip}: {e}")

        return {
            'success': True,
            'message': f'Monitoreados {len(blocks)} bloqueos, {alerts_sent} alertas enviadas',
            'blocks_found': len(blocks),
            'alerts_sent': alerts_sent
        }


# === FUNCIÓN PARA TASK SCHEDULER ===

def fail2ban_monitor_and_alert(limit=50):
    """
    Función wrapper para ejecutar desde task scheduler
    Monitorea bloqueos de Fail2ban y dispara alertas

    Args:
        limit: Número de bloqueos recientes a revisar

    Returns:
        dict: Resumen de la operación
    """
    from database.db_manager import DatabaseManager

    db = DatabaseManager()
    f2b_manager = Fail2banManager(db_manager=db)

    result = f2b_manager.monitor_and_alert_bans(limit=limit)

    return {
        'success': result['success'],
        'message': result['message'],
        'records_processed': result.get('blocks_found', 0),
        'records_created': result.get('alerts_sent', 0)
    }
