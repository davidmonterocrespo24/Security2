"""
Gestor de Base de Datos para Sistema de Seguridad
Maneja todas las operaciones CRUD y consultas
"""

from database.models import *
from sqlalchemy import func, desc, and_, or_
from datetime import datetime, timedelta
import json
import hashlib


class DatabaseManager:
    def __init__(self):
        self.engine = init_database()
        insert_default_config()

    def get_session(self):
        """Obtener nueva sesión de base de datos"""
        Session = sessionmaker(bind=self.engine)
        return Session()

    # ==================== EVENTOS DE SEGURIDAD ====================

    def log_security_event(self, event_type, severity, source_ip, **kwargs):
        """Registrar evento de seguridad"""
        session = self.get_session()
        try:
            event = SecurityEvent(
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                **kwargs
            )
            session.add(event)
            session.commit()
            return event.id
        except Exception as e:
            session.rollback()
            print(f"Error logging security event: {e}")
            return None
        finally:
            session.close()

    def get_recent_events(self, hours=24, limit=100):
        """Obtener eventos recientes"""
        session = self.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            events = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= since
            ).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
            return [e.to_dict() for e in events]
        finally:
            session.close()

    def get_events_by_ip(self, ip_address, limit=50):
        """Obtener eventos de una IP específica"""
        session = self.get_session()
        try:
            events = session.query(SecurityEvent).filter(
                SecurityEvent.source_ip == ip_address
            ).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
            return [e.to_dict() for e in events]
        finally:
            session.close()

    def get_events_by_type(self, event_type, hours=24):
        """Obtener eventos por tipo"""
        session = self.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            events = session.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.event_type == event_type,
                    SecurityEvent.timestamp >= since
                )
            ).order_by(SecurityEvent.timestamp.desc()).all()
            return [e.to_dict() for e in events]
        finally:
            session.close()

    def get_attack_statistics(self, hours=24):
        """Obtener estadísticas de ataques"""
        session = self.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)

            # Total de eventos
            total = session.query(func.count(SecurityEvent.id)).filter(
                SecurityEvent.timestamp >= since
            ).scalar()

            # Por tipo
            by_type = session.query(
                SecurityEvent.event_type,
                func.count(SecurityEvent.id)
            ).filter(
                SecurityEvent.timestamp >= since
            ).group_by(SecurityEvent.event_type).all()

            # Por severidad
            by_severity = session.query(
                SecurityEvent.severity,
                func.count(SecurityEvent.id)
            ).filter(
                SecurityEvent.timestamp >= since
            ).group_by(SecurityEvent.severity).all()

            # IPs únicas
            unique_ips = session.query(
                func.count(func.distinct(SecurityEvent.source_ip))
            ).filter(
                SecurityEvent.timestamp >= since
            ).scalar()

            # Top atacantes
            top_attackers = session.query(
                SecurityEvent.source_ip,
                func.count(SecurityEvent.id).label('count')
            ).filter(
                SecurityEvent.timestamp >= since
            ).group_by(SecurityEvent.source_ip).order_by(desc('count')).limit(10).all()

            return {
                'total_events': total,
                'by_type': dict(by_type),
                'by_severity': dict(by_severity),
                'unique_ips': unique_ips,
                'top_attackers': [{'ip': ip, 'count': count} for ip, count in top_attackers]
            }
        finally:
            session.close()

    # ==================== IPS BLOQUEADAS ====================

    def block_ip(self, ip_address, reason, blocked_by='manual', jail_name=None, threat_level='medium', is_permanent=False):
        """Bloquear una IP"""
        session = self.get_session()
        try:
            # Verificar si ya está bloqueada
            existing = session.query(BlockedIP).filter_by(ip_address=ip_address).first()

            if existing:
                # Actualizar existente
                existing.last_blocked = datetime.utcnow()
                existing.total_attacks += 1
                existing.reason = reason
                existing.threat_level = threat_level
                existing.is_permanent = is_permanent
            else:
                # Crear nuevo
                blocked_ip = BlockedIP(
                    ip_address=ip_address,
                    blocked_by=blocked_by,
                    jail_name=jail_name,
                    reason=reason,
                    threat_level=threat_level,
                    is_permanent=is_permanent
                )
                session.add(blocked_ip)

            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error blocking IP: {e}")
            return False
        finally:
            session.close()

    def unblock_ip(self, ip_address, unblocked_by='manual'):
        """Desbloquear una IP"""
        session = self.get_session()
        try:
            blocked_ip = session.query(BlockedIP).filter_by(ip_address=ip_address).first()
            if blocked_ip:
                blocked_ip.unblocked_at = datetime.utcnow()
                blocked_ip.unblocked_by = unblocked_by
                session.delete(blocked_ip)  # O marcarlo como desbloqueado
                session.commit()
                return True
            return False
        finally:
            session.close()

    def get_blocked_ips(self, include_expired=False):
        """Obtener lista de IPs bloqueadas"""
        session = self.get_session()
        try:
            query = session.query(BlockedIP)

            if not include_expired:
                # Filtrar las que ya expiraron
                now = datetime.utcnow()
                query = query.filter(
                    or_(
                        BlockedIP.is_permanent == True,
                        BlockedIP.unblock_time == None,
                        BlockedIP.unblock_time > now
                    )
                )

            blocked_ips = query.order_by(BlockedIP.last_blocked.desc()).all()
            return [ip.to_dict() for ip in blocked_ips]
        finally:
            session.close()

    def is_ip_blocked(self, ip_address):
        """Verificar si una IP está bloqueada"""
        session = self.get_session()
        try:
            blocked_ip = session.query(BlockedIP).filter_by(ip_address=ip_address).first()
            if not blocked_ip:
                return False

            # Verificar si es permanente
            if blocked_ip.is_permanent:
                return True

            # Verificar si ya expiró
            if blocked_ip.unblock_time and blocked_ip.unblock_time <= datetime.utcnow():
                return False

            return True
        finally:
            session.close()

    def is_ip_whitelisted(self, ip_address):
        """Verificar si una IP está en whitelist"""
        session = self.get_session()
        try:
            whitelist = session.query(IPWhitelist).filter(
                and_(
                    IPWhitelist.ip_address == ip_address,
                    IPWhitelist.is_active == True
                )
            ).first()
            return whitelist is not None
        finally:
            session.close()

    def is_ip_blacklisted(self, ip_address):
        """Verificar si una IP está en blacklist"""
        session = self.get_session()
        try:
            blacklist = session.query(IPBlacklist).filter(
                and_(
                    IPBlacklist.ip_address == ip_address,
                    IPBlacklist.is_active == True
                )
            ).first()
            return blacklist is not None
        finally:
            session.close()

    # ==================== AMENAZAS ====================

    def create_threat(self, threat_type, severity, source, description, **kwargs):
        """Crear alerta de amenaza"""
        session = self.get_session()
        try:
            threat = Threat(
                threat_type=threat_type,
                severity=severity,
                source=source,
                description=description,
                **kwargs
            )
            session.add(threat)
            session.commit()

            # Crear alerta correspondiente
            self.create_alert(
                alert_type='threat_detected',
                severity=severity,
                title=f'Amenaza Detectada: {threat_type}',
                message=description,
                source=source
            )

            return threat.id
        except Exception as e:
            session.rollback()
            print(f"Error creating threat: {e}")
            return None
        finally:
            session.close()

    def get_active_threats(self):
        """Obtener amenazas activas (no resueltas)"""
        session = self.get_session()
        try:
            threats = session.query(Threat).filter(
                and_(
                    Threat.is_resolved == False,
                    Threat.false_positive == False
                )
            ).order_by(Threat.detected_at.desc()).all()
            return [t.to_dict() for t in threats]
        finally:
            session.close()

    def resolve_threat(self, threat_id, resolved_by, resolution_action, notes=None):
        """Marcar amenaza como resuelta"""
        session = self.get_session()
        try:
            threat = session.query(Threat).filter_by(id=threat_id).first()
            if threat:
                threat.is_resolved = True
                threat.resolved_at = datetime.utcnow()
                threat.resolved_by = resolved_by
                threat.resolution_action = resolution_action
                session.commit()
                return True
            return False
        finally:
            session.close()

    # ==================== ALERTAS ====================

    def create_alert(self, alert_type, severity, title, message, source=None, metadata=None):
        """Crear alerta"""
        session = self.get_session()
        try:
            alert = Alert(
                alert_type=alert_type,
                severity=severity,
                title=title,
                message=message,
                source=source,
                metadata=json.dumps(metadata) if metadata else None
            )
            session.add(alert)
            session.commit()
            return alert.id
        except Exception as e:
            session.rollback()
            print(f"Error creating alert: {e}")
            return None
        finally:
            session.close()

    def get_unread_alerts(self):
        """Obtener alertas no leídas"""
        session = self.get_session()
        try:
            alerts = session.query(Alert).filter(
                Alert.is_read == False
            ).order_by(Alert.created_at.desc()).all()
            return [a.to_dict() for a in alerts]
        finally:
            session.close()

    def mark_alert_read(self, alert_id):
        """Marcar alerta como leída"""
        session = self.get_session()
        try:
            alert = session.query(Alert).filter_by(id=alert_id).first()
            if alert:
                alert.is_read = True
                session.commit()
                return True
            return False
        finally:
            session.close()

    # ==================== LOGS DEL SISTEMA ====================

    def log_action(self, log_level, module, action, user_id=None, ip_address=None, details=None, success=True):
        """Registrar acción en logs del sistema"""
        session = self.get_session()
        try:
            log = SystemLog(
                log_level=log_level,
                module=module,
                action=action,
                user_id=user_id,
                ip_address=ip_address,
                details=details,
                success=success
            )
            session.add(log)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error logging action: {e}")
            return False
        finally:
            session.close()

    def get_recent_logs(self, hours=24, limit=100):
        """Obtener logs recientes"""
        session = self.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            logs = session.query(SystemLog).filter(
                SystemLog.timestamp >= since
            ).order_by(SystemLog.timestamp.desc()).limit(limit).all()
            return [l.to_dict() for l in logs]
        finally:
            session.close()

    # ==================== CONFIGURACIÓN ====================

    def get_config(self, key):
        """Obtener valor de configuración"""
        session = self.get_session()
        try:
            config = session.query(SystemConfig).filter_by(config_key=key).first()
            if not config:
                return None

            # Convertir según tipo
            if config.config_type == 'int':
                return int(config.config_value)
            elif config.config_type == 'bool':
                return config.config_value.lower() == 'true'
            elif config.config_type == 'json':
                return json.loads(config.config_value)
            else:
                return config.config_value
        finally:
            session.close()

    def set_config(self, key, value, updated_by='system'):
        """Establecer valor de configuración"""
        session = self.get_session()
        try:
            config = session.query(SystemConfig).filter_by(config_key=key).first()
            if config:
                if config.config_type == 'json':
                    config.config_value = json.dumps(value)
                else:
                    config.config_value = str(value)
                config.updated_at = datetime.utcnow()
                config.updated_by = updated_by
                session.commit()
                return True
            return False
        finally:
            session.close()

    # ==================== ESTADÍSTICAS Y DASHBOARD ====================

    def get_dashboard_stats(self):
        """Obtener estadísticas para el dashboard"""
        session = self.get_session()
        try:
            # Ataques hoy
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            attacks_today = session.query(func.count(SecurityEvent.id)).filter(
                SecurityEvent.timestamp >= today_start
            ).scalar()

            # IPs bloqueadas
            total_blocked = session.query(func.count(BlockedIP.id)).scalar()
            perm_blocked = session.query(func.count(BlockedIP.id)).filter(
                BlockedIP.is_permanent == True
            ).scalar()

            # Amenazas activas
            active_threats = session.query(func.count(Threat.id)).filter(
                Threat.is_resolved == False
            ).scalar()

            # Alertas pendientes
            pending_alerts = session.query(func.count(Alert.id)).filter(
                Alert.is_resolved == False
            ).scalar()

            # Atacantes activos (última hora)
            hour_ago = datetime.utcnow() - timedelta(hours=1)
            active_attackers = session.query(
                func.count(func.distinct(SecurityEvent.source_ip))
            ).filter(
                SecurityEvent.timestamp >= hour_ago
            ).scalar()

            return {
                'attacks_today': attacks_today,
                'total_blocked_ips': total_blocked,
                'permanent_blocked': perm_blocked,
                'active_threats': active_threats,
                'pending_alerts': pending_alerts,
                'active_attackers': active_attackers
            }
        finally:
            session.close()

    # ==================== FAIL2BAN JAILS ====================

    def save_jail_config(self, jail_name, filter_name, log_path, **kwargs):
        """Guardar configuración de jail"""
        session = self.get_session()
        try:
            existing = session.query(Fail2banJail).filter_by(jail_name=jail_name).first()

            if existing:
                # Actualizar
                existing.filter_name = filter_name
                existing.log_path = log_path
                existing.updated_at = datetime.utcnow()
                for key, value in kwargs.items():
                    setattr(existing, key, value)
            else:
                # Crear nueva
                jail = Fail2banJail(
                    jail_name=jail_name,
                    filter_name=filter_name,
                    log_path=log_path,
                    **kwargs
                )
                session.add(jail)

            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error saving jail config: {e}")
            return False
        finally:
            session.close()

    def get_jail_config(self, jail_name):
        """Obtener configuración de jail"""
        session = self.get_session()
        try:
            jail = session.query(Fail2banJail).filter_by(jail_name=jail_name).first()
            return jail.to_dict() if jail else None
        finally:
            session.close()

    def update_jail_stats(self, jail_name, total_bans=None, currently_banned=None):
        """Actualizar estadísticas de jail"""
        session = self.get_session()
        try:
            jail = session.query(Fail2banJail).filter_by(jail_name=jail_name).first()
            if jail:
                if total_bans is not None:
                    jail.total_bans = total_bans
                if currently_banned is not None:
                    jail.currently_banned = currently_banned
                session.commit()
                return True
            return False
        finally:
            session.close()
