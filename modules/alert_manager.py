"""
Alert Manager - Sistema de Alertas y Notificaciones
Envía alertas por email (SMTP) basándose en reglas configurables
"""

import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from jinja2 import Template
from database.models import AlertChannel, AlertRule, AlertLog
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()


class AlertManager:
    """Gestor de alertas y notificaciones"""

    def __init__(self, db_manager):
        self.db = db_manager

    def send_email(self, recipients, subject, body, html_body=None):
        """
        Enviar email vía SMTP

        Args:
            recipients (list): Lista de emails destinatarios
            subject (str): Asunto del email
            body (str): Cuerpo del email (texto plano)
            html_body (str, optional): Cuerpo del email en HTML

        Returns:
            dict: {'success': bool, 'error': str o None, 'duration_ms': int}
        """
        start_time = datetime.now()

        try:
            # Obtener configuración SMTP desde .env
            smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = int(os.getenv('SMTP_PORT', 587))
            smtp_user = os.getenv('SMTP_USER', '')
            smtp_password = os.getenv('SMTP_PASSWORD', '')
            smtp_from = os.getenv('SMTP_FROM', smtp_user)

            # Validar configuración
            if not smtp_user or not smtp_password:
                return {
                    'success': False,
                    'error': 'SMTP credentials not configured in .env file',
                    'duration_ms': 0
                }

            if not recipients:
                return {
                    'success': False,
                    'error': 'No recipients specified',
                    'duration_ms': 0
                }

            # Crear mensaje
            msg = MIMEMultipart('alternative')
            msg['From'] = smtp_from
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')

            # Agregar cuerpo en texto plano
            part_text = MIMEText(body, 'plain', 'utf-8')
            msg.attach(part_text)

            # Agregar cuerpo en HTML si se proporciona
            if html_body:
                part_html = MIMEText(html_body, 'html', 'utf-8')
                msg.attach(part_html)

            # Conectar y enviar
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, recipients, msg.as_string())
            server.quit()

            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

            return {
                'success': True,
                'error': None,
                'duration_ms': duration_ms
            }

        except smtplib.SMTPAuthenticationError as e:
            return {
                'success': False,
                'error': f'SMTP authentication failed: {str(e)}',
                'duration_ms': int((datetime.now() - start_time).total_seconds() * 1000)
            }
        except smtplib.SMTPException as e:
            return {
                'success': False,
                'error': f'SMTP error: {str(e)}',
                'duration_ms': int((datetime.now() - start_time).total_seconds() * 1000)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'duration_ms': int((datetime.now() - start_time).total_seconds() * 1000)
            }

    def evaluate_rule(self, rule, event):
        """
        Evaluar si un evento cumple con las condiciones de una regla

        Args:
            rule (AlertRule): Regla a evaluar
            event (dict): Evento con datos

        Returns:
            bool: True si cumple condiciones, False si no
        """
        try:
            # Parse condiciones de la regla
            conditions = json.loads(rule.conditions)

            # Evaluar cada condición
            for field, condition in conditions.items():
                operator = condition.get('operator')
                value = condition.get('value')

                # Obtener valor del evento
                event_value = event.get(field)

                # Evaluar según operador
                if operator == '>':
                    if not (event_value is not None and event_value > value):
                        return False
                elif operator == '<':
                    if not (event_value is not None and event_value < value):
                        return False
                elif operator == '==':
                    if event_value != value:
                        return False
                elif operator == '!=':
                    if event_value == value:
                        return False
                elif operator == '>=':
                    if not (event_value is not None and event_value >= value):
                        return False
                elif operator == '<=':
                    if not (event_value is not None and event_value <= value):
                        return False
                elif operator == 'in':
                    if not (event_value and event_value in value):
                        return False
                elif operator == 'not_in':
                    if event_value and event_value in value:
                        return False
                elif operator == 'contains':
                    if not (event_value and value in str(event_value)):
                        return False
                else:
                    # Operador desconocido
                    return False

            # Todas las condiciones cumplidas
            return True

        except Exception as e:
            print(f"Error evaluating rule {rule.rule_name}: {e}")
            return False

    def format_alert_message(self, template_str, event):
        """
        Formatear mensaje de alerta usando plantilla Jinja2

        Args:
            template_str (str): Plantilla Jinja2
            event (dict): Datos del evento

        Returns:
            str: Mensaje formateado
        """
        try:
            if not template_str:
                # Mensaje por defecto si no hay plantilla
                return f"Alert: {event.get('type', 'Unknown')} - {event.get('message', 'No details')}"

            template = Template(template_str)
            return template.render(**event)

        except Exception as e:
            print(f"Error formatting message: {e}")
            return f"Alert: {event.get('type', 'Unknown')} (Error formatting message)"

    def check_cooldown(self, rule):
        """
        Verificar si una regla está en cooldown (no debe disparar alerta aún)

        Args:
            rule (AlertRule): Regla a verificar

        Returns:
            bool: True si está en cooldown, False si puede disparar
        """
        if rule.cooldown_minutes == 0:
            return False  # Sin cooldown

        if not rule.last_triggered_at:
            return False  # Nunca se ha disparado

        # Calcular tiempo transcurrido
        now = datetime.utcnow()
        cooldown_end = rule.last_triggered_at + timedelta(minutes=rule.cooldown_minutes)

        return now < cooldown_end

    def process_alert(self, event):
        """
        Procesar un evento y disparar alertas si corresponde

        Args:
            event (dict): Evento a procesar
                Ejemplo:
                {
                    'type': 'ml_prediction',
                    'severity': 'HIGH',
                    'ip': '1.2.3.4',
                    'ml_confidence': 0.95,
                    'country': 'CN',
                    'reason': 'Multiple failed login attempts',
                    ...
                }

        Returns:
            dict: {'alerts_sent': int, 'errors': list}
        """
        session = self.db.get_session()
        alerts_sent = 0
        errors = []

        try:
            # Obtener tipo de evento
            event_type = event.get('type', 'unknown')

            # Mapear tipo de evento a rule_type
            rule_type_mapping = {
                'ml_prediction': 'ml_prediction',
                'zeek_detection': 'zeek_detection',
                'fail2ban_ban': 'fail2ban_ban'
            }

            rule_type = rule_type_mapping.get(event_type, 'custom')

            # Obtener reglas activas para este tipo
            rules = session.query(AlertRule).filter_by(
                rule_type=rule_type,
                is_enabled=True
            ).all()

            for rule in rules:
                # Verificar cooldown
                if self.check_cooldown(rule):
                    continue

                # Evaluar condiciones
                if not self.evaluate_rule(rule, event):
                    continue

                # Verificar umbral de severidad
                if rule.severity_threshold:
                    severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                    event_severity = event.get('severity', 'LOW')
                    rule_severity = rule.severity_threshold

                    if event_severity not in severity_levels or rule_severity not in severity_levels:
                        continue

                    event_level = severity_levels.index(event_severity)
                    rule_level = severity_levels.index(rule_severity)

                    if event_level < rule_level:
                        continue

                # La regla se debe disparar - obtener canales
                channel_ids = json.loads(rule.channel_ids) if rule.channel_ids else []

                for channel_id in channel_ids:
                    channel = session.query(AlertChannel).filter_by(
                        id=channel_id,
                        is_enabled=True
                    ).first()

                    if not channel:
                        continue

                    # Formatear mensajes
                    subject = self.format_alert_message(rule.subject_template, event)
                    message = self.format_alert_message(rule.message_template, event)

                    # Enviar según tipo de canal
                    result = None

                    if channel.channel_type == 'email':
                        result = self._send_via_email_channel(channel, subject, message, event)

                    # Log del envío
                    alert_log = AlertLog(
                        rule_id=rule.id,
                        channel_id=channel.id,
                        severity=event.get('severity', 'MEDIUM'),
                        subject=subject,
                        message=message,
                        event_metadata=json.dumps(event),
                        success=result['success'] if result else False,
                        error_message=result['error'] if result else 'Channel type not supported',
                        send_duration_ms=result['duration_ms'] if result else 0
                    )
                    session.add(alert_log)

                    # Actualizar estadísticas del canal
                    channel.total_alerts_sent += 1
                    if result and result['success']:
                        channel.successful_sends += 1
                        channel.last_alert_sent_at = datetime.utcnow()
                        alerts_sent += 1
                    else:
                        channel.failed_sends += 1
                        errors.append({
                            'channel': channel.channel_name,
                            'error': result['error'] if result else 'Channel type not supported'
                        })

                # Actualizar estadísticas de la regla
                rule.total_triggers += 1
                rule.last_triggered_at = datetime.utcnow()
                if alerts_sent > 0:
                    rule.total_alerts_sent += alerts_sent

            session.commit()

        except Exception as e:
            session.rollback()
            errors.append({'error': f'Unexpected error: {str(e)}'})
            print(f"Error processing alert: {e}")

        finally:
            session.close()

        return {
            'alerts_sent': alerts_sent,
            'errors': errors
        }

    def _send_via_email_channel(self, channel, subject, message, event):
        """
        Enviar alerta vía canal de email

        Args:
            channel (AlertChannel): Canal de email
            subject (str): Asunto
            message (str): Mensaje
            event (dict): Evento original

        Returns:
            dict: Resultado del envío
        """
        try:
            # Parse configuración del canal
            config = json.loads(channel.config)
            recipients = config.get('recipients', [])

            # Si no hay recipients en config, usar ALERT_EMAIL_TO de .env
            if not recipients:
                env_recipients = os.getenv('ALERT_EMAIL_TO', '')
                if env_recipients:
                    recipients = [email.strip() for email in env_recipients.split(',')]

            if not recipients:
                return {
                    'success': False,
                    'error': 'No recipients configured',
                    'duration_ms': 0
                }

            # Generar HTML body
            html_body = self._generate_html_email(subject, message, event)

            # Enviar email
            return self.send_email(recipients, subject, message, html_body)

        except Exception as e:
            return {
                'success': False,
                'error': f'Error sending via email channel: {str(e)}',
                'duration_ms': 0
            }

    def _generate_html_email(self, subject, message, event):
        """
        Generar HTML body para email

        Args:
            subject (str): Asunto
            message (str): Mensaje en texto plano
            event (dict): Evento con datos

        Returns:
            str: HTML formateado
        """
        severity_colors = {
            'LOW': '#10b981',      # green
            'MEDIUM': '#f59e0b',   # yellow
            'HIGH': '#f97316',     # orange
            'CRITICAL': '#ef4444'  # red
        }

        severity = event.get('severity', 'MEDIUM')
        color = severity_colors.get(severity, '#6b7280')

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: {color}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .header h2 {{ margin: 0; }}
        .content {{ background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; }}
        .footer {{ background: #f3f4f6; padding: 15px; text-align: center; font-size: 12px; color: #6b7280; border-radius: 0 0 8px 8px; }}
        .severity {{ display: inline-block; padding: 5px 10px; background: {color}; color: white; border-radius: 4px; font-weight: bold; }}
        .details {{ margin-top: 20px; }}
        .detail-row {{ margin: 8px 0; }}
        .label {{ font-weight: bold; color: #374151; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>{subject}</h2>
        </div>
        <div class="content">
            <div>
                <span class="severity">{severity}</span>
            </div>
            <div style="margin-top: 20px; white-space: pre-wrap;">{message}</div>
            <div class="details">
                <h3>Detalles del Evento:</h3>
"""

        # Agregar detalles del evento
        for key, value in event.items():
            if key not in ['type', 'severity', 'message']:
                html += f'<div class="detail-row"><span class="label">{key}:</span> {value}</div>\n'

        html += f"""
            </div>
        </div>
        <div class="footer">
            <p>Security Alert System</p>
            <p>Enviado: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def test_channel(self, channel_id):
        """
        Enviar mensaje de prueba a un canal

        Args:
            channel_id (int): ID del canal

        Returns:
            dict: {'success': bool, 'error': str o None}
        """
        session = self.db.get_session()

        try:
            channel = session.query(AlertChannel).filter_by(id=channel_id).first()

            if not channel:
                return {'success': False, 'error': 'Channel not found'}

            # Mensaje de prueba
            test_event = {
                'type': 'test',
                'severity': 'LOW',
                'message': 'Este es un mensaje de prueba del sistema de alertas.',
                'timestamp': datetime.utcnow().isoformat()
            }

            subject = 'Test - Security Alert System'
            message = 'Si recibes este mensaje, el canal de alertas esta funcionando correctamente.'

            result = None

            if channel.channel_type == 'email':
                result = self._send_via_email_channel(channel, subject, message, test_event)

            # Actualizar canal
            if result:
                channel.last_test_at = datetime.utcnow()
                channel.last_test_success = result['success']
                if result['success']:
                    channel.is_verified = True
                session.commit()

            session.close()
            return result if result else {'success': False, 'error': 'Channel type not supported'}

        except Exception as e:
            session.rollback()
            session.close()
            return {'success': False, 'error': str(e)}

    def get_alert_stats(self, hours=24):
        """
        Obtener estadísticas de alertas

        Args:
            hours (int): Horas hacia atrás

        Returns:
            dict: Estadísticas
        """
        session = self.db.get_session()

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)

            logs = session.query(AlertLog).filter(
                AlertLog.sent_at >= cutoff
            ).all()

            total = len(logs)
            successful = len([l for l in logs if l.success])
            failed = total - successful

            by_severity = {}
            by_channel = {}

            for log in logs:
                # Por severidad
                sev = log.severity
                by_severity[sev] = by_severity.get(sev, 0) + 1

                # Por canal
                if log.channel_id:
                    by_channel[log.channel_id] = by_channel.get(log.channel_id, 0) + 1

            session.close()

            return {
                'total_alerts': total,
                'successful': successful,
                'failed': failed,
                'success_rate': (successful / total * 100) if total > 0 else 0,
                'by_severity': by_severity,
                'by_channel': by_channel
            }

        except Exception as e:
            session.close()
            return {
                'error': str(e),
                'total_alerts': 0,
                'successful': 0,
                'failed': 0
            }
