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
        """Obtener estadísticas completas de ataques incluyendo datos geográficos"""
        session = self.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)

            # Total de eventos
            total = session.query(func.count(SecurityEvent.id)).filter(
                SecurityEvent.timestamp >= since
            ).scalar()

            # Por tipo de ataque
            by_type = session.query(
                SecurityEvent.event_type,
                func.count(SecurityEvent.id)
            ).filter(
                SecurityEvent.timestamp >= since
            ).group_by(SecurityEvent.event_type).all()

            # Por severidad
            by_severity_data = session.query(
                SecurityEvent.severity,
                func.count(SecurityEvent.id)
            ).filter(
                SecurityEvent.timestamp >= since
            ).group_by(SecurityEvent.severity).all()

            by_severity_dict = dict(by_severity_data)

            # IPs únicas
            unique_ips = session.query(
                func.count(func.distinct(SecurityEvent.source_ip))
            ).filter(
                SecurityEvent.timestamp >= since
            ).scalar()

            # Top atacantes con información completa
            top_ips_query = session.query(
                SecurityEvent.source_ip,
                func.count(SecurityEvent.id).label('count'),
                func.max(SecurityEvent.severity).label('max_severity'),
                func.max(SecurityEvent.country).label('country')
            ).filter(
                SecurityEvent.timestamp >= since
            ).group_by(SecurityEvent.source_ip).order_by(desc('count')).limit(10).all()

            top_ips = []
            for ip, count, max_severity, country in top_ips_query:
                # Verificar si está bloqueada
                blocked = session.query(BlockedIP).filter(
                    and_(
                        BlockedIP.ip_address == ip,
                        or_(
                            BlockedIP.is_permanent == True,
                            BlockedIP.unblock_time > datetime.utcnow()
                        )
                    )
                ).first()

                top_ips.append({
                    'ip_address': ip,
                    'count': count,
                    'max_severity': max_severity or 'low',
                    'country': country or 'Unknown',
                    'is_blocked': blocked is not None
                })

            # Estadísticas por país
            by_country_data = session.query(
                SecurityEvent.country,
                func.count(SecurityEvent.id)
            ).filter(
                SecurityEvent.timestamp >= since
            ).group_by(SecurityEvent.country).all()

            by_country = {}
            for country, count in by_country_data:
                if country and country not in ['Unknown', 'unknown', None, '']:
                    by_country[country] = count

            # Estadísticas horarias
            hourly_stats = []
            interval_hours = min(hours, 24)
            interval_minutes = (hours * 60) // interval_hours

            for i in range(interval_hours):
                interval_start = since + timedelta(minutes=i * interval_minutes)
                interval_end = interval_start + timedelta(minutes=interval_minutes)

                interval_events = session.query(
                    SecurityEvent.severity,
                    func.count(SecurityEvent.id)
                ).filter(
                    and_(
                        SecurityEvent.timestamp >= interval_start,
                        SecurityEvent.timestamp < interval_end
                    )
                ).group_by(SecurityEvent.severity).all()

                severity_counts = dict(interval_events)
                hourly_stats.append({
                    'hour': interval_start.strftime('%H:%M'),
                    'critical': severity_counts.get('critical', 0),
                    'high': severity_counts.get('high', 0),
                    'medium': severity_counts.get('medium', 0),
                    'low': severity_counts.get('low', 0)
                })

            # Datos geográficos para el mapa
            geo_data = []
            for ip, count, severity, country in top_ips_query[:20]:
                if country and country not in ['Unknown', 'unknown', None, '']:
                    geo_data.append({
                        'ip': ip,
                        'country': country,
                        'count': count,
                        'severity': severity or 'low',
                        'lat': None,
                        'lon': None
                    })

            return {
                'total_events': total,
                'by_attack_type': dict(by_type),
                'by_type': dict(by_type),  # Compatibilidad
                'by_severity': {
                    'critical': by_severity_dict.get('critical', 0),
                    'high': by_severity_dict.get('high', 0),
                    'medium': by_severity_dict.get('medium', 0),
                    'low': by_severity_dict.get('low', 0)
                },
                'unique_ips': unique_ips,
                'top_ips': top_ips,
                'top_attackers': [{'ip': ip, 'count': count} for ip, count in top_ips_query],  # Compatibilidad
                'by_country': by_country,
                'hourly_stats': hourly_stats,
                'geo_data': geo_data
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

    # ==================== MÉTODOS ADICIONALES PARA ML Y API ====================

    def get_security_events(self, limit=100, severity=None, event_type=None):
        """Obtener eventos de seguridad con filtros opcionales"""
        session = self.get_session()
        try:
            query = session.query(SecurityEvent)

            if severity:
                query = query.filter(SecurityEvent.severity == severity)

            if event_type:
                query = query.filter(SecurityEvent.event_type == event_type)

            events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
            return [e.to_dict() for e in events]
        finally:
            session.close()

    def get_event_by_id(self, event_id):
        """Obtener evento específico por ID"""
        session = self.get_session()
        try:
            event = session.query(SecurityEvent).filter_by(id=event_id).first()
            return event.to_dict() if event else None
        finally:
            session.close()

    def get_alerts(self, status='pending', severity=None, limit=50):
        """Obtener alertas con filtros"""
        session = self.get_session()
        try:
            query = session.query(Alert)

            if status == 'pending':
                query = query.filter(Alert.is_resolved == False)
            elif status == 'resolved':
                query = query.filter(Alert.is_resolved == True)
            elif status == 'dismissed':
                query = query.filter(Alert.is_read == True, Alert.is_resolved == False)

            if severity:
                query = query.filter(Alert.severity == severity)

            alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()
            return [a.to_dict() for a in alerts]
        finally:
            session.close()

    def resolve_alert(self, alert_id, resolved_by, resolution_notes=''):
        """Resolver una alerta"""
        session = self.get_session()
        try:
            alert = session.query(Alert).filter_by(id=alert_id).first()
            if alert:
                alert.is_resolved = True
                alert.resolved_at = datetime.utcnow()
                alert.resolved_by = resolved_by
                alert.action_taken = resolution_notes
                alert.is_read = True
                session.commit()
                return True
            return False
        finally:
            session.close()

    def dismiss_alert(self, alert_id):
        """Descartar una alerta (marcar como leída sin resolver)"""
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

    def block_ip(self, ip_address, reason, blocked_by='manual', duration_hours=24, jail_name=None, threat_level='medium'):
        """Bloquear una IP con duración"""
        session = self.get_session()
        try:
            # Calcular tiempo de desbloqueo
            unblock_time = datetime.utcnow() + timedelta(hours=duration_hours) if duration_hours else None
            is_permanent = duration_hours is None or duration_hours <= 0

            # Verificar si ya está bloqueada
            existing = session.query(BlockedIP).filter_by(ip_address=ip_address).first()

            if existing:
                # Actualizar existente
                existing.last_blocked = datetime.utcnow()
                existing.total_attacks += 1
                existing.reason = reason
                existing.threat_level = threat_level
                existing.is_permanent = is_permanent
                existing.unblock_time = unblock_time
            else:
                # Crear nuevo
                blocked_ip = BlockedIP(
                    ip_address=ip_address,
                    blocked_by=blocked_by,
                    jail_name=jail_name,
                    reason=reason,
                    threat_level=threat_level,
                    is_permanent=is_permanent,
                    unblock_time=unblock_time
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

    def get_blocked_ips(self, ip=None, include_expired=False):
        """Obtener IPs bloqueadas"""
        session = self.get_session()
        try:
            query = session.query(BlockedIP)

            if ip:
                query = query.filter(BlockedIP.ip_address == ip)

            if not include_expired:
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

    def add_to_whitelist(self, ip_address, reason, added_by):
        """Agregar IP a whitelist"""
        session = self.get_session()
        try:
            existing = session.query(IPWhitelist).filter_by(ip_address=ip_address).first()

            if existing:
                existing.is_active = True
                existing.reason = reason
            else:
                whitelist = IPWhitelist(
                    ip_address=ip_address,
                    reason=reason,
                    added_by=added_by,
                    is_active=True
                )
                session.add(whitelist)

            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error adding to whitelist: {e}")
            return False
        finally:
            session.close()

    def remove_from_whitelist(self, ip_address):
        """Remover IP de whitelist"""
        session = self.get_session()
        try:
            whitelist = session.query(IPWhitelist).filter_by(ip_address=ip_address).first()
            if whitelist:
                session.delete(whitelist)
                session.commit()
                return True
            return False
        finally:
            session.close()

    def get_whitelist(self):
        """Obtener whitelist completa"""
        session = self.get_session()
        try:
            whitelist = session.query(IPWhitelist).filter_by(is_active=True).all()
            return [w.to_dict() for w in whitelist]
        finally:
            session.close()

    def add_to_blacklist(self, ip_address, reason, added_by):
        """Agregar IP a blacklist"""
        session = self.get_session()
        try:
            existing = session.query(IPBlacklist).filter_by(ip_address=ip_address).first()

            if existing:
                existing.is_active = True
                existing.reason = reason
            else:
                blacklist = IPBlacklist(
                    ip_address=ip_address,
                    reason=reason,
                    added_by=added_by,
                    is_active=True,
                    threat_score=100
                )
                session.add(blacklist)

            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error adding to blacklist: {e}")
            return False
        finally:
            session.close()

    def get_blacklist(self):
        """Obtener blacklist completa"""
        session = self.get_session()
        try:
            blacklist = session.query(IPBlacklist).filter_by(is_active=True).all()
            return [b.to_dict() for b in blacklist]
        finally:
            session.close()

    def get_dashboard_stats(self):
        """Obtener estadísticas del dashboard mejoradas"""
        session = self.get_session()
        try:
            # Eventos últimas 24h
            day_ago = datetime.utcnow() - timedelta(hours=24)
            total_events_24h = session.query(func.count(SecurityEvent.id)).filter(
                SecurityEvent.timestamp >= day_ago
            ).scalar()

            critical_events_24h = session.query(func.count(SecurityEvent.id)).filter(
                and_(
                    SecurityEvent.timestamp >= day_ago,
                    SecurityEvent.severity == 'critical'
                )
            ).scalar()

            # IPs bloqueadas
            total_blocked_ips = session.query(func.count(BlockedIP.id)).filter(
                or_(
                    BlockedIP.is_permanent == True,
                    BlockedIP.unblock_time > datetime.utcnow()
                )
            ).scalar()

            # Amenazas activas
            active_threats = session.query(func.count(Threat.id)).filter(
                Threat.is_resolved == False
            ).scalar()

            # Alertas pendientes
            pending_alerts = session.query(func.count(Alert.id)).filter(
                Alert.is_resolved == False
            ).scalar()

            return {
                'total_events_24h': total_events_24h or 0,
                'critical_events_24h': critical_events_24h or 0,
                'total_blocked_ips': total_blocked_ips or 0,
                'blocked_ips': total_blocked_ips or 0,  # Alias
                'active_threats': active_threats or 0,
                'pending_alerts': pending_alerts or 0
            }
        finally:
            session.close()

    # ==================== CONFIGURACIÓN GEOGRÁFICA ====================

    def get_geo_config(self):
        """Obtener configuración de filtrado geográfico"""
        session = self.get_session()
        try:
            config = session.query(GeoConfig).first()
            if config:
                return config.to_dict()

            # Si no existe, crear configuración por defecto
            default_config = GeoConfig(
                enabled=False,
                mode='whitelist',
                countries='[]',
                block_unknown=False,
                updated_by='system'
            )
            session.add(default_config)
            session.commit()
            return default_config.to_dict()
        finally:
            session.close()

    def update_geo_config(self, enabled=None, mode=None, countries=None, block_unknown=None, updated_by='system'):
        """Actualizar configuración de filtrado geográfico"""
        session = self.get_session()
        try:
            config = session.query(GeoConfig).first()

            if not config:
                # Crear nueva configuración
                config = GeoConfig()
                session.add(config)

            # Actualizar campos proporcionados
            if enabled is not None:
                config.enabled = enabled
            if mode is not None:
                config.mode = mode
            if countries is not None:
                # Convertir lista a JSON
                if isinstance(countries, list):
                    config.countries = json.dumps(countries)
                else:
                    config.countries = countries
            if block_unknown is not None:
                config.block_unknown = block_unknown

            config.updated_at = datetime.utcnow()
            config.updated_by = updated_by

            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error updating geo config: {e}")
            return False
        finally:
            session.close()

    def add_country_to_filter(self, country_code, updated_by='system'):
        """Agregar un país a la lista de filtrado"""
        session = self.get_session()
        try:
            config = session.query(GeoConfig).first()

            if not config:
                # Crear configuración si no existe
                config = GeoConfig(
                    countries=json.dumps([country_code]),
                    updated_by=updated_by
                )
                session.add(config)
            else:
                # Agregar a lista existente
                countries = json.loads(config.countries) if config.countries else []
                if country_code not in countries:
                    countries.append(country_code)
                    config.countries = json.dumps(countries)
                    config.updated_at = datetime.utcnow()
                    config.updated_by = updated_by

            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error adding country to filter: {e}")
            return False
        finally:
            session.close()

    def remove_country_from_filter(self, country_code, updated_by='system'):
        """Remover un país de la lista de filtrado"""
        session = self.get_session()
        try:
            config = session.query(GeoConfig).first()

            if config and config.countries:
                countries = json.loads(config.countries)
                if country_code in countries:
                    countries.remove(country_code)
                    config.countries = json.dumps(countries)
                    config.updated_at = datetime.utcnow()
                    config.updated_by = updated_by
                    session.commit()
                    return True

            return False
        except Exception as e:
            session.rollback()
            print(f"Error removing country from filter: {e}")
            return False
        finally:
            session.close()

    # ==================== CACHÉ DE PREDICCIONES ML ====================

    def save_ml_prediction(self, ip_address, prediction_data, model_version='1.0'):
        """Guardar predicción ML para una IP en caché"""
        session = self.get_session()
        try:
            # Buscar predicción existente
            existing = session.query(MLPrediction).filter_by(ip_address=ip_address).first()

            if existing:
                # Actualizar existente
                existing.analyzed_at = datetime.utcnow()
                existing.ml_confidence = prediction_data.get('ml_confidence', 0.0)
                existing.is_suspicious = prediction_data.get('ml_confidence', 0.0) >= 0.6
                existing.is_anomaly = prediction_data.get('is_anomaly', False)
                existing.total_events = prediction_data.get('total_events', 0)
                existing.suspicious_events = prediction_data.get('suspicious_events', 0)
                existing.anomaly_events = prediction_data.get('anomaly_events', 0)
                existing.country = prediction_data.get('country', 'Unknown')
                existing.country_code = prediction_data.get('country_code', 'XX')

                # Convertir fechas a objetos datetime si vienen como strings
                first_seen = prediction_data.get('first_seen')
                if first_seen and isinstance(first_seen, str):
                    try:
                        first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                    except:
                        first_seen = None
                existing.first_seen = first_seen

                last_seen = prediction_data.get('last_seen')
                if last_seen and isinstance(last_seen, str):
                    try:
                        last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    except:
                        last_seen = None
                existing.last_seen = last_seen
                existing.reasons = prediction_data.get('reasons', '')
                existing.recommended_action = prediction_data.get('recommended_action', 'monitor')
                existing.is_blocked = prediction_data.get('is_blocked', False)
                existing.model_version = model_version
                existing.is_valid = True
                # Nuevos campos de mejoras ML
                existing.threat_score = prediction_data.get('threat_score', 0.0)
                existing.action_text = prediction_data.get('action_text', '')
                existing.behavioral_features = json.dumps(prediction_data.get('behavioral_features', {}))
                existing.threat_factors = json.dumps(prediction_data.get('threat_factors', []))
                existing.requests_per_minute = prediction_data.get('requests_per_minute', 0.0)
                existing.error_ratio = prediction_data.get('error_ratio', 0.0)
                existing.is_bot = prediction_data.get('is_bot', False)
            else:
                # Crear nueva predicción

                # Convertir fechas a objetos datetime si vienen como strings
                first_seen = prediction_data.get('first_seen')
                if first_seen and isinstance(first_seen, str):
                    try:
                        first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                    except:
                        first_seen = datetime.utcnow()
                elif not first_seen:
                    first_seen = datetime.utcnow()

                last_seen = prediction_data.get('last_seen')
                if last_seen and isinstance(last_seen, str):
                    try:
                        last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    except:
                        last_seen = datetime.utcnow()
                elif not last_seen:
                    last_seen = datetime.utcnow()

                prediction = MLPrediction(
                    ip_address=ip_address,
                    ml_confidence=prediction_data.get('ml_confidence', 0.0),
                    is_suspicious=prediction_data.get('ml_confidence', 0.0) >= 0.6,
                    is_anomaly=prediction_data.get('is_anomaly', False),
                    total_events=prediction_data.get('total_events', 0),
                    suspicious_events=prediction_data.get('suspicious_events', 0),
                    anomaly_events=prediction_data.get('anomaly_events', 0),
                    country=prediction_data.get('country', 'Unknown'),
                    country_code=prediction_data.get('country_code', 'XX'),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    reasons=prediction_data.get('reasons', ''),
                    recommended_action=prediction_data.get('recommended_action', 'monitor'),
                    is_blocked=prediction_data.get('is_blocked', False),
                    model_version=model_version,
                    is_valid=True,
                    # Nuevos campos de mejoras ML
                    threat_score=prediction_data.get('threat_score', 0.0),
                    action_text=prediction_data.get('action_text', ''),
                    behavioral_features=json.dumps(prediction_data.get('behavioral_features', {})),
                    threat_factors=json.dumps(prediction_data.get('threat_factors', [])),
                    requests_per_minute=prediction_data.get('requests_per_minute', 0.0),
                    error_ratio=prediction_data.get('error_ratio', 0.0),
                    is_bot=prediction_data.get('is_bot', False)
                )
                session.add(prediction)

            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error saving ML prediction: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            session.close()

    def get_ml_predictions(self, hours_back=24, min_confidence=0.6, only_valid=True):
        """Obtener predicciones ML en caché"""
        session = self.get_session()
        try:
            # Calcular cutoff time
            try:
                if hours_back > 24 * 365:
                    days_back = hours_back / 24
                    cutoff_time = datetime.utcnow() - timedelta(days=days_back)
                else:
                    cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
            except OverflowError:
                cutoff_time = datetime.utcnow() - timedelta(days=365)

            query = session.query(MLPrediction).filter(
                MLPrediction.ml_confidence >= min_confidence,
                MLPrediction.last_seen >= cutoff_time  # Filtrar por última actividad
            )

            if only_valid:
                query = query.filter(MLPrediction.is_valid == True)

            predictions = query.order_by(desc(MLPrediction.threat_score)).all()

            return [pred.to_dict() for pred in predictions]
        finally:
            session.close()

    def invalidate_ml_predictions(self):
        """Invalidar todas las predicciones ML (cuando se re-entrena el modelo)"""
        session = self.get_session()
        try:
            session.query(MLPrediction).update({'is_valid': False})
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            print(f"Error invalidating ML predictions: {e}")
            return False
        finally:
            session.close()

    def cleanup_old_predictions(self, days_old=30):
        """Eliminar predicciones más antiguas de X días"""
        session = self.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(days=days_old)

            deleted = session.query(MLPrediction).filter(
                MLPrediction.analyzed_at < cutoff
            ).delete()

            session.commit()
            print(f"🗑️  Eliminadas {deleted} predicciones antiguas")
            return deleted
        except Exception as e:
            session.rollback()
            print(f"Error cleaning up predictions: {e}")
            return 0
        finally:
            session.close()
