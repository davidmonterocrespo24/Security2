"""
Escáner de Puertos del Sistema
"""
import psutil
import subprocess


class PortScanner:
    def __init__(self):
        self.open_ports = []

    def scan(self):
        """Escanear puertos abiertos en el sistema"""
        try:
            connections = psutil.net_connections(kind='inet')
            ports_info = []

            for conn in connections:
                if conn.status == 'LISTEN':
                    port_info = {
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'pid': conn.pid,
                        'status': conn.status
                    }

                    # Obtener información del proceso
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            port_info['process_name'] = process.name()
                            port_info['process_exe'] = process.exe()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            port_info['process_name'] = 'Unknown'
                            port_info['process_exe'] = 'Unknown'

                    # Identificar servicio común
                    port_info['service'] = self._identify_service(conn.laddr.port)

                    ports_info.append(port_info)

            # Eliminar duplicados
            unique_ports = {}
            for port in ports_info:
                key = f"{port['port']}_{port['address']}"
                if key not in unique_ports:
                    unique_ports[key] = port

            self.open_ports = list(unique_ports.values())

            return {
                'success': True,
                'count': len(self.open_ports),
                'ports': self.open_ports
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _identify_service(self, port):
        """Identificar servicio común por puerto"""
        common_ports = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP (Submission)',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8000: 'HTTP Alt',
            8080: 'HTTP Proxy',
            8069: 'Odoo',
            8443: 'HTTPS Alt',
            27017: 'MongoDB',
        }

        return common_ports.get(port, 'Unknown')

    def get_open_ports(self):
        """Obtener lista de puertos abiertos"""
        return self.open_ports

    def get_open_ports_count(self):
        """Obtener cantidad de puertos abiertos"""
        return len(self.open_ports)

    def check_port_security(self, port):
        """Verificar seguridad de un puerto"""
        warnings = []

        # Puertos peligrosos expuestos
        dangerous_ports = [23, 21, 20, 3389, 5900]  # Telnet, FTP, RDP, VNC
        if port in dangerous_ports:
            warnings.append('This port is considered insecure')

        # Bases de datos expuestas
        db_ports = [3306, 5432, 27017, 6379]
        if port in db_ports:
            warnings.append('Database port - should not be exposed publicly')

        return {
            'port': port,
            'warnings': warnings,
            'risk_level': 'high' if warnings else 'low'
        }

    def get_listening_services(self):
        """Obtener servicios que están escuchando"""
        services = []

        for port_info in self.open_ports:
            service = {
                'name': port_info.get('service', 'Unknown'),
                'port': port_info['port'],
                'process': port_info.get('process_name', 'Unknown'),
                'address': port_info['address']
            }
            services.append(service)

        return services

    def scan_external_ports(self, target='127.0.0.1'):
        """Escanear puertos usando nmap (si está disponible)"""
        try:
            result = subprocess.run(
                ['nmap', '-sV', target],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return {
                    'success': True,
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'error': 'nmap scan failed'
                }
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'nmap not installed'
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Scan timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
