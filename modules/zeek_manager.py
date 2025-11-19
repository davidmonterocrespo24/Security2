"""
Módulo de gestión de Zeek Network Security Monitor
Manejo de instalación, configuración, inicio/detención del servicio
"""

import subprocess
import os
import json
import shutil
from datetime import datetime
from pathlib import Path


class ZeekManager:
    """Gestor de Zeek Network Security Monitor"""

    def __init__(self, db_manager):
        self.db = db_manager
        self.zeek_binary = self._find_zeek_binary()
        self.zeekctl_binary = self._find_zeekctl_binary()

    def _find_zeek_binary(self):
        """Encontrar el binario de Zeek"""
        possible_paths = [
            '/opt/zeek/bin/zeek',
            '/usr/local/zeek/bin/zeek',
            '/usr/bin/zeek',
            shutil.which('zeek')
        ]

        for path in possible_paths:
            if path and os.path.exists(path):
                return path

        return None

    def _find_zeekctl_binary(self):
        """Encontrar el binario de zeekctl"""
        possible_paths = [
            '/opt/zeek/bin/zeekctl',
            '/usr/local/zeek/bin/zeekctl',
            '/usr/bin/zeekctl',
            shutil.which('zeekctl')
        ]

        for path in possible_paths:
            if path and os.path.exists(path):
                return path

        return None

    def check_zeek_installed(self):
        """
        Verificar si Zeek está instalado

        Returns:
            dict: {
                'installed': bool,
                'version': str or None,
                'path': str or None,
                'zeekctl_available': bool
            }
        """
        is_installed = self.zeek_binary is not None
        version = None
        zeekctl_available = self.zeekctl_binary is not None

        if is_installed:
            try:
                result = subprocess.run(
                    [self.zeek_binary, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Parsear versión
                    output = result.stdout.strip()
                    if 'version' in output.lower():
                        version = output.split('\n')[0]
            except Exception as e:
                print(f"Error obteniendo versión de Zeek: {e}")

        return {
            'installed': is_installed,
            'version': version,
            'path': self.zeek_binary,
            'zeekctl_available': zeekctl_available
        }

    def install_zeek(self, method='package'):
        """
        Instalar Zeek

        Args:
            method: 'package' (desde repos) o 'source' (compilar)

        Returns:
            dict: {
                'success': bool,
                'message': str,
                'output': str
            }
        """
        if self.check_zeek_installed()['installed']:
            return {
                'success': False,
                'message': 'Zeek ya está instalado',
                'output': ''
            }

        try:
            if method == 'package':
                return self._install_from_package()
            elif method == 'source':
                return {
                    'success': False,
                    'message': 'Instalación desde source no implementada aún',
                    'output': ''
                }
            else:
                return {
                    'success': False,
                    'message': f'Método de instalación desconocido: {method}',
                    'output': ''
                }
        except Exception as e:
            return {
                'success': False,
                'message': f'Error durante la instalación: {str(e)}',
                'output': ''
            }

    def _install_from_package(self):
        """Instalar Zeek desde repositorio oficial"""
        steps_output = []

        try:
            # Detectar distribución
            distro_info = self._detect_distribution()
            steps_output.append(f"Distribución detectada: {distro_info['name']} {distro_info['version']}")

            # Ubuntu/Debian
            if distro_info['family'] == 'debian':
                steps_output.append("\n=== Instalando Zeek en Debian/Ubuntu ===")

                # 1. Instalar dependencias
                steps_output.append("1. Instalando dependencias...")
                result = subprocess.run(
                    ['apt-get', 'update'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                steps_output.append(result.stdout + result.stderr)

                # 2. Agregar repositorio oficial de Zeek
                steps_output.append("2. Agregando repositorio oficial de Zeek...")

                # Instalar herramientas necesarias
                subprocess.run(
                    ['apt-get', 'install', '-y', 'curl', 'gnupg', 'lsb-release'],
                    capture_output=True,
                    timeout=300
                )

                # Agregar clave GPG
                steps_output.append("   Agregando clave GPG de Zeek...")
                subprocess.run(
                    ['bash', '-c', 'curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_$(lsb_release -rs)/Release.key | gpg --dearmor | tee /usr/share/keyrings/zeek-archive-keyring.gpg > /dev/null'],
                    capture_output=True,
                    timeout=60
                )

                # Agregar repositorio
                steps_output.append("   Agregando repositorio...")
                subprocess.run(
                    ['bash', '-c', 'echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] https://download.opensuse.org/repositories/security:/zeek/xUbuntu_$(lsb_release -rs)/ /" | tee /etc/apt/sources.list.d/zeek.list'],
                    capture_output=True,
                    timeout=30
                )

                # 3. Actualizar caché de paquetes
                steps_output.append("3. Actualizando caché de paquetes...")
                result = subprocess.run(
                    ['apt-get', 'update'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                steps_output.append(result.stdout + result.stderr)

                # 4. Instalar Zeek
                steps_output.append("4. Instalando Zeek...")
                result = subprocess.run(
                    ['apt-get', 'install', '-y', 'zeek'],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                steps_output.append(result.stdout + result.stderr)

                if result.returncode != 0:
                    return {
                        'success': False,
                        'message': 'Error instalando Zeek',
                        'output': '\n'.join(steps_output)
                    }

                # 5. Crear symlinks
                steps_output.append("5. Creando symlinks...")
                zeek_paths = ['/opt/zeek/bin', '/usr/local/zeek/bin']
                for zeek_path in zeek_paths:
                    if os.path.exists(zeek_path):
                        # Agregar a PATH
                        profile_path = '/etc/profile.d/zeek.sh'
                        with open(profile_path, 'w') as f:
                            f.write(f'export PATH={zeek_path}:$PATH\n')
                        steps_output.append(f"   Agregado {zeek_path} a PATH")
                        break

                # Actualizar referencias a binarios
                self.zeek_binary = self._find_zeek_binary()
                self.zeekctl_binary = self._find_zeekctl_binary()

                # 6. Guardar configuración en BD
                self._save_zeek_config({
                    'is_installed': True,
                    'zeek_version': self.get_zeek_version(),
                    'install_path': os.path.dirname(self.zeek_binary) if self.zeek_binary else None,
                    'log_dir': '/opt/zeek/logs/current' if os.path.exists('/opt/zeek') else '/usr/local/zeek/logs/current'
                })

                return {
                    'success': True,
                    'message': 'Zeek instalado correctamente',
                    'output': '\n'.join(steps_output)
                }

            else:
                return {
                    'success': False,
                    'message': f'Distribución no soportada: {distro_info["family"]}',
                    'output': '\n'.join(steps_output)
                }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'message': 'Timeout durante la instalación',
                'output': '\n'.join(steps_output)
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Error: {str(e)}',
                'output': '\n'.join(steps_output)
            }

    def _detect_distribution(self):
        """Detectar distribución de Linux"""
        try:
            # Leer /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    info = {}
                    for line in lines:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            info[key] = value.strip('"')

                    name = info.get('ID', 'unknown')
                    version = info.get('VERSION_ID', '0')

                    # Determinar familia
                    if name in ['ubuntu', 'debian']:
                        family = 'debian'
                    elif name in ['centos', 'rhel', 'fedora']:
                        family = 'redhat'
                    else:
                        family = 'unknown'

                    return {
                        'name': name,
                        'version': version,
                        'family': family
                    }
        except:
            pass

        return {
            'name': 'unknown',
            'version': '0',
            'family': 'unknown'
        }

    def get_zeek_version(self):
        """Obtener versión de Zeek instalada"""
        check = self.check_zeek_installed()
        return check.get('version', 'Unknown')

    def get_zeek_status(self):
        """
        Obtener estado del servicio de Zeek

        Returns:
            dict: {
                'running': bool,
                'nodes': list,
                'uptime': str,
                'errors': list
            }
        """
        if not self.zeekctl_binary:
            return {
                'running': False,
                'nodes': [],
                'uptime': None,
                'errors': ['zeekctl no disponible']
            }

        try:
            # Usar sudo con ruta completa
            result = subprocess.run(
                ['sudo', self.zeekctl_binary, 'status'],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout.strip()
            lines = output.split('\n')

            nodes = []
            running = False

            for line in lines:
                if 'running' in line.lower():
                    running = True
                    # Parsear línea de status
                    parts = line.split()
                    if len(parts) >= 2:
                        nodes.append({
                            'name': parts[0],
                            'status': 'running' if 'running' in line.lower() else 'stopped'
                        })

            return {
                'running': running,
                'nodes': nodes,
                'uptime': None,  # TODO: parsear uptime
                'errors': []
            }

        except Exception as e:
            return {
                'running': False,
                'nodes': [],
                'uptime': None,
                'errors': [str(e)]
            }

    def start_zeek(self, interface=None):
        """
        Iniciar Zeek

        Args:
            interface: Interfaz de red a monitorear (ej: eth0)

        Returns:
            dict: {'success': bool, 'message': str, 'output': str}
        """
        if not self.zeekctl_binary:
            return {
                'success': False,
                'message': 'zeekctl no disponible',
                'output': ''
            }

        try:
            # Si no se proporciona interfaz, usar la interfaz por defecto
            if not interface:
                interface = self.get_default_interface()

            # Si se proporciona interfaz, configurarla
            if interface:
                self.configure_zeek(interface=interface)

            # Deploy de configuración usando sudo con ruta completa
            result = subprocess.run(
                ['sudo', self.zeekctl_binary, 'deploy'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                # Actualizar estado en BD
                self._update_zeek_status(is_running=True)

                return {
                    'success': True,
                    'message': 'Zeek iniciado correctamente',
                    'output': result.stdout + result.stderr
                }
            else:
                return {
                    'success': False,
                    'message': 'Error iniciando Zeek',
                    'output': result.stdout + result.stderr
                }

        except Exception as e:
            return {
                'success': False,
                'message': f'Error: {str(e)}',
                'output': ''
            }

    def stop_zeek(self):
        """
        Detener Zeek

        Returns:
            dict: {'success': bool, 'message': str, 'output': str}
        """
        if not self.zeekctl_binary:
            return {
                'success': False,
                'message': 'zeekctl no disponible',
                'output': ''
            }

        try:
            # Usar sudo con ruta completa
            result = subprocess.run(
                ['sudo', self.zeekctl_binary, 'stop'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                # Actualizar estado en BD
                self._update_zeek_status(is_running=False)

                return {
                    'success': True,
                    'message': 'Zeek detenido correctamente',
                    'output': result.stdout + result.stderr
                }
            else:
                return {
                    'success': False,
                    'message': 'Error deteniendo Zeek',
                    'output': result.stdout + result.stderr
                }

        except Exception as e:
            return {
                'success': False,
                'message': f'Error: {str(e)}',
                'output': ''
            }

    def restart_zeek(self):
        """
        Reiniciar Zeek

        Returns:
            dict: {'success': bool, 'message': str, 'output': str}
        """
        stop_result = self.stop_zeek()
        if not stop_result['success']:
            return stop_result

        import time
        time.sleep(2)

        return self.start_zeek()

    def get_interfaces(self):
        """
        Obtener interfaces de red disponibles

        Returns:
            list: [{'name': str, 'ip': str, 'status': str}, ...]
        """
        interfaces = []

        try:
            # Usar 'ip link show' para listar interfaces
            result = subprocess.run(
                ['ip', 'link', 'show'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                lines = result.stdout.split('\n')

                for line in lines:
                    # Línea de interfaz: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                    if line and line[0].isdigit() and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            iface_name = parts[1].strip()

                            # Filtrar interfaces especiales
                            if iface_name in ['lo', 'docker0'] or iface_name.startswith('br-') or iface_name.startswith('veth'):
                                continue

                            status = 'UP' if 'UP' in line and 'LOWER_UP' in line else 'DOWN'

                            interface = {
                                'name': iface_name,
                                'ip': None,
                                'status': status
                            }

                            # Obtener IP de la interfaz
                            ip_result = subprocess.run(
                                ['ip', 'addr', 'show', iface_name],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )

                            if ip_result.returncode == 0:
                                for ip_line in ip_result.stdout.split('\n'):
                                    if 'inet ' in ip_line and 'inet6' not in ip_line:
                                        ip_parts = ip_line.strip().split()
                                        if len(ip_parts) >= 2:
                                            ip_with_mask = ip_parts[1]
                                            interface['ip'] = ip_with_mask.split('/')[0]
                                            break

                            interfaces.append(interface)

        except Exception as e:
            print(f"Error obteniendo interfaces: {e}")

        return interfaces

    def get_default_interface(self):
        """
        Obtener la interfaz de red principal (por defecto)

        Returns:
            str: Nombre de la interfaz (ej: eth0)
        """
        interfaces = self.get_interfaces()

        # Filtrar interfaces UP con IP
        active_interfaces = [
            iface for iface in interfaces
            if iface['status'] == 'UP' and iface['ip'] is not None
        ]

        # Preferir eth0, luego cualquier ethX, luego cualquier otra
        for iface in active_interfaces:
            if iface['name'] == 'eth0':
                return 'eth0'

        for iface in active_interfaces:
            if iface['name'].startswith('eth'):
                return iface['name']

        # Si no hay eth, devolver la primera activa
        if active_interfaces:
            return active_interfaces[0]['name']

        return None

    def configure_zeek(self, interface=None, log_dir=None, options=None):
        """
        Configurar Zeek

        Args:
            interface: Interfaz de red a monitorear
            log_dir: Directorio de logs
            options: Dict con opciones adicionales

        Returns:
            dict: {'success': bool, 'message': str}
        """
        config_updates = {}

        if interface:
            config_updates['monitored_interface'] = interface
            # Actualizar node.cfg
            self._update_node_cfg(interface)

        if log_dir:
            config_updates['log_dir'] = log_dir

        if options:
            config_updates.update(options)

        # Guardar en BD
        self._save_zeek_config(config_updates)

        return {
            'success': True,
            'message': 'Configuración actualizada'
        }

    def _update_node_cfg(self, interface):
        """Actualizar archivo node.cfg con la interfaz"""
        node_cfg_paths = [
            '/opt/zeek/etc/node.cfg',
            '/usr/local/zeek/etc/node.cfg',
            '/etc/zeek/node.cfg'
        ]

        for cfg_path in node_cfg_paths:
            if os.path.exists(cfg_path):
                try:
                    # Leer archivo
                    with open(cfg_path, 'r') as f:
                        lines = f.readlines()

                    # Modificar línea de interface
                    new_lines = []
                    for line in lines:
                        if line.strip().startswith('interface='):
                            new_lines.append(f'interface={interface}\n')
                        else:
                            new_lines.append(line)

                    # Escribir archivo usando sudo (requiere permisos)
                    # Crear archivo temporal
                    temp_file = '/tmp/node.cfg.tmp'
                    with open(temp_file, 'w') as f:
                        f.writelines(new_lines)

                    # Mover con sudo
                    subprocess.run(
                        ['sudo', 'mv', temp_file, cfg_path],
                        capture_output=True,
                        timeout=10
                    )

                    return True
                except Exception as e:
                    print(f"Error actualizando node.cfg: {e}")

        return False

    def get_log_files(self):
        """
        Obtener lista de archivos de log de Zeek

        Returns:
            dict: {
                'conn': str (path),
                'dns': str,
                'ssl': str,
                'http': str,
                ...
            }
        """
        log_dirs = [
            '/opt/zeek/logs/current',
            '/usr/local/zeek/logs/current',
            '/var/log/zeek/current'
        ]

        log_files = {}

        for log_dir in log_dirs:
            if os.path.exists(log_dir):
                # Buscar archivos .log
                for file_type in ['conn', 'dns', 'ssl', 'http', 'files', 'notice', 'weird']:
                    log_file = os.path.join(log_dir, f'{file_type}.log')
                    if os.path.exists(log_file):
                        log_files[file_type] = log_file

                break

        return log_files

    def deploy_zeek_scripts(self, scripts):
        """
        Desplegar scripts personalizados de Zeek

        Args:
            scripts: Dict con {script_name: script_content}

        Returns:
            dict: {'success': bool, 'deployed': list}
        """
        script_dirs = [
            '/opt/zeek/share/zeek/site',
            '/usr/local/zeek/share/zeek/site'
        ]

        deployed = []

        for script_dir in script_dirs:
            if os.path.exists(script_dir):
                try:
                    for script_name, script_content in scripts.items():
                        script_path = os.path.join(script_dir, script_name)

                        with open(script_path, 'w') as f:
                            f.write(script_content)

                        deployed.append(script_name)

                    return {
                        'success': True,
                        'deployed': deployed
                    }
                except Exception as e:
                    return {
                        'success': False,
                        'deployed': deployed,
                        'error': str(e)
                    }

        return {
            'success': False,
            'deployed': [],
            'error': 'Script directory not found'
        }

    def _save_zeek_config(self, config_dict):
        """Guardar configuración de Zeek en BD"""
        from database.models import ZeekConfig

        session = self.db.get_session()

        try:
            # Buscar config existente
            zeek_config = session.query(ZeekConfig).first()

            if not zeek_config:
                zeek_config = ZeekConfig()
                session.add(zeek_config)

            # Actualizar campos
            for key, value in config_dict.items():
                if hasattr(zeek_config, key):
                    setattr(zeek_config, key, value)

            zeek_config.updated_at = datetime.utcnow()

            session.commit()
        finally:
            session.close()

    def _update_zeek_status(self, is_running):
        """Actualizar estado de ejecución de Zeek"""
        from database.models import ZeekConfig

        session = self.db.get_session()

        try:
            zeek_config = session.query(ZeekConfig).first()

            if not zeek_config:
                zeek_config = ZeekConfig()
                session.add(zeek_config)

            zeek_config.is_running = is_running

            if is_running:
                zeek_config.last_started = datetime.utcnow()
            else:
                zeek_config.last_stopped = datetime.utcnow()

            session.commit()
        finally:
            session.close()

    def get_config(self):
        """Obtener configuración de Zeek desde BD"""
        from database.models import ZeekConfig

        session = self.db.get_session()

        try:
            zeek_config = session.query(ZeekConfig).first()

            if zeek_config:
                return zeek_config.to_dict()
            else:
                return {
                    'is_installed': False,
                    'is_running': False
                }
        finally:
            session.close()
