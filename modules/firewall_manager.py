"""
Gestor de Firewall (UFW)
"""
import subprocess
import re


class FirewallManager:
    def __init__(self):
        self.ufw_available = self._check_ufw_available()

    def _check_ufw_available(self):
        """Verificar si UFW está disponible"""
        try:
            result = subprocess.run(['which', 'ufw'], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def _run_command(self, command):
        """Ejecutar comando del sistema"""
        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
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

    def get_status(self):
        """Obtener estado del firewall"""
        if not self.ufw_available:
            return {
                'enabled': False,
                'available': False,
                'message': 'UFW no está instalado'
            }

        result = self._run_command('sudo ufw status verbose')
        if result['success']:
            output = result['output']
            enabled = 'Status: active' in output
            return {
                'enabled': enabled,
                'available': True,
                'output': output
            }
        else:
            return {
                'enabled': False,
                'available': True,
                'error': result.get('error')
            }

    def get_rules(self):
        """Obtener reglas del firewall"""
        if not self.ufw_available:
            return []

        result = self._run_command('sudo ufw status numbered')
        if not result['success']:
            return []

        rules = []
        lines = result['output'].split('\n')
        for line in lines:
            # Parsear líneas como: [ 1] 22/tcp                     ALLOW IN    Anywhere
            match = re.match(r'\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(.+)', line)
            if match:
                rules.append({
                    'number': int(match.group(1)),
                    'rule': match.group(2).strip(),
                    'action': match.group(3),
                    'direction': match.group(4),
                    'from': match.group(5).strip()
                })

        return rules

    def get_rules_count(self):
        """Obtener cantidad de reglas"""
        return len(self.get_rules())

    def add_rule(self, rule_data):
        """Agregar regla al firewall"""
        if not self.ufw_available:
            return {'success': False, 'error': 'UFW no disponible'}

        action = rule_data.get('action', 'allow').lower()
        port = rule_data.get('port')
        protocol = rule_data.get('protocol', 'tcp')
        from_ip = rule_data.get('from_ip', 'any')
        direction = rule_data.get('direction', 'in')

        # Construir comando
        if from_ip and from_ip != 'any':
            command = f"sudo ufw {action} from {from_ip} to any port {port} proto {protocol}"
        else:
            command = f"sudo ufw {action} {port}/{protocol}"

        result = self._run_command(command)
        return result

    def delete_rule(self, rule_number):
        """Eliminar regla del firewall"""
        if not self.ufw_available:
            return {'success': False, 'error': 'UFW no disponible'}

        command = f"echo 'y' | sudo ufw delete {rule_number}"
        result = self._run_command(command)
        return result

    def toggle(self, enable=True):
        """Activar/desactivar firewall"""
        if not self.ufw_available:
            return {'success': False, 'error': 'UFW no disponible'}

        if enable:
            # CRÍTICO: Asegurar que SSH esté permitido antes de activar el firewall
            # Esto previene que el usuario quede bloqueado fuera del servidor
            ssh_result = self._ensure_ssh_allowed()
            if not ssh_result['success']:
                return {
                    'success': False,
                    'error': 'No se pudo asegurar acceso SSH. Firewall NO activado por seguridad.',
                    'details': ssh_result.get('error')
                }

            command = "echo 'y' | sudo ufw enable"
        else:
            command = "sudo ufw disable"

        result = self._run_command(command)

        # Si se activó correctamente, informar sobre SSH
        if result['success'] and enable:
            result['message'] = 'Firewall activado. SSH permitido automáticamente para prevenir bloqueo.'

        return result

    def _ensure_ssh_allowed(self):
        """Asegurar que SSH esté permitido antes de activar firewall"""
        # Permitir SSH en el puerto 22
        result1 = self._run_command('sudo ufw allow 22/tcp')
        result2 = self._run_command('sudo ufw allow ssh')

        if result1['success'] or result2['success']:
            return {'success': True, 'message': 'SSH permitido'}
        else:
            return {'success': False, 'error': 'No se pudo permitir SSH'}

    def reset(self):
        """Resetear firewall a valores por defecto"""
        if not self.ufw_available:
            return {'success': False, 'error': 'UFW no disponible'}

        command = "echo 'y' | sudo ufw reset"
        result = self._run_command(command)
        return result

    def allow_service(self, service):
        """Permitir servicio común (ssh, http, https, etc.)"""
        if not self.ufw_available:
            return {'success': False, 'error': 'UFW no disponible'}

        command = f"sudo ufw allow {service}"
        result = self._run_command(command)
        return result

    def deny_ip(self, ip):
        """Denegar IP específica"""
        if not self.ufw_available:
            return {'success': False, 'error': 'UFW no disponible'}

        command = f"sudo ufw deny from {ip}"
        result = self._run_command(command)
        return result
