"""
Instalador de Componentes del Sistema
"""
import subprocess
import os
from .config_manager import ConfigManager


class SystemInstaller:
    def __init__(self):
        self.config_manager = ConfigManager()

    def _run_command(self, command):
        """Ejecutar comando del sistema"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                shell=True
            )
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def check_system_requirements(self):
        """Verificar requisitos del sistema"""
        requirements = {
            'os': self._check_os(),
            'python': self._check_python(),
            'sudo': self._check_sudo(),
        }

        return requirements

    def _check_os(self):
        """Verificar sistema operativo"""
        result = self._run_command('uname -a')
        is_linux = 'Linux' in result.get('output', '')

        return {
            'met': is_linux,
            'message': 'Linux detected' if is_linux else 'This system requires Linux (Ubuntu)'
        }

    def _check_python(self):
        """Verificar versión de Python"""
        result = self._run_command('python3 --version')
        has_python = result['success']

        return {
            'met': has_python,
            'message': result.get('output', 'Python 3 not found')
        }

    def _check_sudo(self):
        """Verificar acceso sudo"""
        result = self._run_command('sudo -n true 2>/dev/null')
        has_sudo = result['success']

        return {
            'met': has_sudo,
            'message': 'Sudo access available' if has_sudo else 'Sudo access required'
        }

    def install_components(self, config):
        """Instalar componentes necesarios"""
        results = []

        # Actualizar configuración
        self.config_manager.save_config(config)

        # 1. Actualizar paquetes del sistema
        results.append({
            'component': 'System Update',
            'result': self._update_system()
        })

        # 2. Instalar Fail2ban
        if config.get('install_fail2ban', True):
            results.append({
                'component': 'Fail2ban',
                'result': self._install_fail2ban()
            })

        # 3. Instalar UFW
        if config.get('install_ufw', True):
            results.append({
                'component': 'UFW Firewall',
                'result': self._install_ufw()
            })

        # 4. Configurar Fail2ban para Nginx
        if config.get('nginx_path'):
            results.append({
                'component': 'Nginx Fail2ban Filter',
                'result': self._configure_nginx_fail2ban(config)
            })

        # 5. Configurar Fail2ban para SSH
        results.append({
            'component': 'SSH Fail2ban Filter',
            'result': self._configure_ssh_fail2ban()
        })

        # Marcar como instalado
        self.config_manager.mark_as_installed()

        return {
            'success': True,
            'results': results
        }

    def _update_system(self):
        """Actualizar paquetes del sistema"""
        result = self._run_command('sudo apt-get update')
        return result

    def _install_fail2ban(self):
        """Instalar Fail2ban"""
        # Verificar si ya está instalado
        check = self._run_command('which fail2ban-client')
        if check['success']:
            return {
                'success': True,
                'message': 'Fail2ban already installed'
            }

        # Instalar
        result = self._run_command('sudo apt-get install -y fail2ban')
        if result['success']:
            # Habilitar y arrancar servicio
            self._run_command('sudo systemctl enable fail2ban')
            self._run_command('sudo systemctl start fail2ban')

        return result

    def _install_ufw(self):
        """Instalar UFW"""
        # Verificar si ya está instalado
        check = self._run_command('which ufw')
        if check['success']:
            return {
                'success': True,
                'message': 'UFW already installed'
            }

        # Instalar
        result = self._run_command('sudo apt-get install -y ufw')
        return result

    def _configure_nginx_fail2ban(self, config):
        """Configurar Fail2ban para Nginx"""
        nginx_log_path = config.get('nginx_log_path', '/var/log/nginx')

        # Crear filtro para límite de peticiones
        filter_config = f"""
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*" (4|5)\\d{{2}}
ignoreregex =
"""

        # Guardar filtro
        filter_path = '/etc/fail2ban/filter.d/nginx-req-limit.conf'
        try:
            with open('/tmp/nginx-req-limit.conf', 'w') as f:
                f.write(filter_config)

            self._run_command(f'sudo mv /tmp/nginx-req-limit.conf {filter_path}')

            # Crear jail
            jail_config = f"""
[nginx-req-limit]
enabled = true
port = http,https
filter = nginx-req-limit
logpath = {nginx_log_path}/access.log
maxretry = 100
findtime = 60
bantime = 3600
"""

            with open('/tmp/nginx-jail.local', 'w') as f:
                f.write(jail_config)

            self._run_command('sudo mv /tmp/nginx-jail.local /etc/fail2ban/jail.d/nginx-req-limit.local')

            # Reiniciar fail2ban
            self._run_command('sudo systemctl restart fail2ban')

            return {'success': True, 'message': 'Nginx filter configured'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _configure_ssh_fail2ban(self):
        """Configurar Fail2ban para SSH"""
        jail_config = """
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 600
bantime = 3600
"""

        try:
            with open('/tmp/sshd-jail.local', 'w') as f:
                f.write(jail_config)

            self._run_command('sudo mv /tmp/sshd-jail.local /etc/fail2ban/jail.d/sshd.local')
            self._run_command('sudo systemctl restart fail2ban')

            return {'success': True, 'message': 'SSH filter configured'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def create_bot_blocker_filter(self):
        """Crear filtro para bloquear bots"""
        filter_config = """
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*".*"(bot|crawler|spider|scraper|curl|wget|python-requests|axios).*"
ignoreregex = (Googlebot|bingbot|YandexBot)
"""

        jail_config = """
[http-bot-blocker]
enabled = true
port = http,https
filter = http-bot-blocker
logpath = /var/log/nginx/access.log
maxretry = 50
findtime = 300
bantime = 7200
"""

        try:
            # Crear filtro
            with open('/tmp/http-bot-blocker.conf', 'w') as f:
                f.write(filter_config)

            self._run_command('sudo mv /tmp/http-bot-blocker.conf /etc/fail2ban/filter.d/http-bot-blocker.conf')

            # Crear jail
            with open('/tmp/bot-blocker-jail.local', 'w') as f:
                f.write(jail_config)

            self._run_command('sudo mv /tmp/bot-blocker-jail.local /etc/fail2ban/jail.d/http-bot-blocker.local')
            self._run_command('sudo systemctl restart fail2ban')

            return {'success': True, 'message': 'Bot blocker filter created'}

        except Exception as e:
            return {'success': False, 'error': str(e)}
