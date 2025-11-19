"""
Script para migrar la base de datos y agregar nuevas tablas
"""

from database.models import init_database, get_session, AlertChannel, AlertRule, AlertLog
import json
from datetime import datetime

def migrate():
    """Ejecutar migración de base de datos"""
    print("="*60)
    print("MIGRACIÓN DE BASE DE DATOS")
    print("="*60)

    # Crear todas las tablas (incluyendo las nuevas)
    print("\n1. Creando tablas nuevas...")
    engine = init_database()
    print("[OK] Tablas creadas correctamente")

    # Crear datos por defecto
    print("\n2. Creando datos por defecto...")
    session = get_session()

    # Verificar si ya existen canales
    existing_channels = session.query(AlertChannel).count()

    if existing_channels == 0:
        print("   > Creando canal de email por defecto...")

        # Canal de email por defecto (se configurará desde .env)
        default_email_channel = AlertChannel(
            channel_name='Email Principal',
            channel_type='email',
            description='Canal de email principal para alertas de seguridad',
            config=json.dumps({
                'smtp_server': '',  # Se cargará desde .env
                'smtp_port': 587,
                'smtp_user': '',    # Se cargará desde .env
                'smtp_password': '', # Se cargará desde .env
                'recipients': []     # Se cargará desde .env
            }),
            is_enabled=False,  # Deshabilitado hasta configurar
            created_by='system'
        )
        session.add(default_email_channel)
        session.commit()
        print("   [OK] Canal de email creado (ID: {})".format(default_email_channel.id))

        # Crear reglas de alerta por defecto
        print("   > Creando reglas de alerta por defecto...")

        default_rules = [
            {
                'rule_name': 'ML Alta Confianza',
                'description': 'Alertar cuando ML detecta IP maliciosa con confianza > 80%',
                'rule_type': 'ml_prediction',
                'conditions': json.dumps({'ml_confidence': {'operator': '>', 'value': 0.8}}),
                'severity_threshold': 'HIGH',
                'channel_ids': json.dumps([default_email_channel.id]),
                'cooldown_minutes': 30,
                'subject_template': 'Alerta de Seguridad - ML Deteccion',
                'message_template': '''IP Sospechosa Detectada por Machine Learning

IP: {{ip}}
Confianza: {{confidence}}%
País: {{country}}
Razón: {{reason}}

Esta IP ha sido detectada como maliciosa con alta confianza.
''',
                'created_by': 'system'
            },
            {
                'rule_name': 'Zeek Port Scan',
                'description': 'Alertar cuando Zeek detecta escaneo de puertos',
                'rule_type': 'zeek_detection',
                'conditions': json.dumps({'detection_type': {'operator': '==', 'value': 'port_scan'}}),
                'severity_threshold': 'HIGH',
                'channel_ids': json.dumps([default_email_channel.id]),
                'cooldown_minutes': 15,
                'subject_template': 'Alerta de Seguridad - Port Scan Detectado',
                'message_template': '''Port Scan Detectado por Zeek

IP Origen: {{ip}}
Puertos Escaneados: {{ports_count}}
Protocolo: {{protocol}}

Un escaneo de puertos ha sido detectado desde esta IP.
''',
                'created_by': 'system'
            },
            {
                'rule_name': 'Zeek DNS Tunneling',
                'description': 'Alertar cuando Zeek detecta DNS tunneling',
                'rule_type': 'zeek_detection',
                'conditions': json.dumps({'detection_type': {'operator': '==', 'value': 'dns_tunneling'}}),
                'severity_threshold': 'HIGH',
                'channel_ids': json.dumps([default_email_channel.id]),
                'cooldown_minutes': 30,
                'subject_template': 'Alerta de Seguridad - DNS Tunneling',
                'message_template': '''DNS Tunneling Detectado por Zeek

IP Origen: {{ip}}
Dominios: {{domains_count}}
Queries Sospechosas: {{queries}}

Posible exfiltración de datos vía DNS.
''',
                'created_by': 'system'
            },
            {
                'rule_name': 'Zeek Beaconing (C&C)',
                'description': 'Alertar cuando Zeek detecta comunicación con C&C',
                'rule_type': 'zeek_detection',
                'conditions': json.dumps({'detection_type': {'operator': '==', 'value': 'beaconing'}}),
                'severity_threshold': 'CRITICAL',
                'channel_ids': json.dumps([default_email_channel.id]),
                'cooldown_minutes': 5,
                'subject_template': 'CRITICO - Beaconing Detectado (Posible C&C)',
                'message_template': '''ALERTA CRÍTICA: Beaconing Detectado

IP Origen: {{ip}}
IP Destino: {{dest_ip}}
Regularidad: {{regularity}}
Conexiones: {{connections}}

Posible comunicación con servidor Command & Control.
ACCIÓN INMEDIATA REQUERIDA.
''',
                'created_by': 'system'
            },
            {
                'rule_name': 'Fail2ban Ban Crítico',
                'description': 'Alertar cuando Fail2ban banea IP de país de alto riesgo',
                'rule_type': 'fail2ban_ban',
                'conditions': json.dumps({'country': {'operator': 'in', 'value': ['CN', 'RU', 'KP', 'IR']}}),
                'severity_threshold': 'MEDIUM',
                'channel_ids': json.dumps([default_email_channel.id]),
                'cooldown_minutes': 60,
                'subject_template': 'Alerta - IP Baneada por Fail2ban',
                'message_template': '''IP Baneada por Fail2ban

IP: {{ip}}
País: {{country}}
Jail: {{jail}}
Razón: {{reason}}

Una IP de país de alto riesgo ha sido baneada.
''',
                'created_by': 'system'
            }
        ]

        for rule_data in default_rules:
            rule = AlertRule(**rule_data)
            rule.is_enabled = False  # Deshabilitadas hasta configurar canal de email
            session.add(rule)

        session.commit()
        print("   [OK] {} reglas de alerta creadas".format(len(default_rules)))
    else:
        print("   [INFO] Ya existen canales de alerta configurados (skip)")

    session.close()

    print("\n" + "="*60)
    print("[OK] MIGRACION COMPLETADA")
    print("="*60)
    print("\nProximos pasos:")
    print("1. Configurar credenciales SMTP en archivo .env")
    print("2. Acceder a panel web > Configuracion de Alertas")
    print("3. Configurar canal de email y activar reglas")
    print()

if __name__ == '__main__':
    migrate()
