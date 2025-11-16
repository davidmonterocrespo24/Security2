"""
Gestor de Configuración del Sistema
"""
import json
import os


class ConfigManager:
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.default_config = {
            "odoo_path": "",
            "postgres_path": "",
            "nginx_path": "/etc/nginx",
            "nginx_log_path": "/var/log/nginx",
            "fail2ban_path": "/etc/fail2ban",
            "ssh_log_path": "/var/log/auth.log",
            "installed": False,
            "secret_key": "change-this-secret-key-in-production"
        }

    def load_config(self):
        """Cargar configuración desde archivo"""
        if not os.path.exists(self.config_file):
            self.save_config(self.default_config)
            return self.default_config

        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                return config
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.default_config

    def save_config(self, config):
        """Guardar configuración en archivo"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def get(self, key, default=None):
        """Obtener valor de configuración"""
        config = self.load_config()
        return config.get(key, default)

    def set(self, key, value):
        """Establecer valor de configuración"""
        config = self.load_config()
        config[key] = value
        return self.save_config(config)

    def is_installed(self):
        """Verificar si el sistema está instalado"""
        return self.get('installed', False)

    def mark_as_installed(self):
        """Marcar el sistema como instalado"""
        return self.set('installed', True)
