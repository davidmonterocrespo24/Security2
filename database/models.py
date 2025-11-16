"""
Modelos de Base de Datos para Sistema de Seguridad
Usando SQLAlchemy ORM con SQLite
"""

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timedelta
import json
import os

Base = declarative_base()

# Ruta de la base de datos
DB_PATH = os.path.join(os.path.dirname(__file__), 'security.db')
DATABASE_URL = f'sqlite:///{DB_PATH}'

class SecurityEvent(Base):
    """Eventos de seguridad detectados"""
    __tablename__ = 'security_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)
    source_ip = Column(String, nullable=False, index=True)
    target_port = Column(Integer)
    protocol = Column(String)
    attack_vector = Column(String)
    details = Column(Text)
    user_agent = Column(Text)
    request_path = Column(Text)
    payload = Column(Text)
    geo_location = Column(String)
    is_blocked = Column(Boolean, default=False)
    blocked_by = Column(String)
    false_positive = Column(Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'target_port': self.target_port,
            'protocol': self.protocol,
            'attack_vector': self.attack_vector,
            'details': self.details,
            'is_blocked': self.is_blocked,
            'blocked_by': self.blocked_by
        }


class BlockedIP(Base):
    """IPs bloqueadas por el sistema"""
    __tablename__ = 'blocked_ips'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String, unique=True, nullable=False, index=True)
    first_blocked = Column(DateTime, default=datetime.utcnow)
    last_blocked = Column(DateTime, default=datetime.utcnow)
    blocked_by = Column(String, nullable=False)
    jail_name = Column(String)
    reason = Column(Text, nullable=False)
    threat_level = Column(String, default='medium', index=True)
    total_attacks = Column(Integer, default=1)
    attack_types = Column(Text)  # JSON
    is_permanent = Column(Boolean, default=False, index=True)
    unblock_time = Column(DateTime)
    unblocked_at = Column(DateTime)
    unblocked_by = Column(String)
    notes = Column(Text)
    country = Column(String)
    asn = Column(String)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'first_blocked': self.first_blocked.isoformat() if self.first_blocked else None,
            'last_blocked': self.last_blocked.isoformat() if self.last_blocked else None,
            'blocked_by': self.blocked_by,
            'jail_name': self.jail_name,
            'reason': self.reason,
            'threat_level': self.threat_level,
            'total_attacks': self.total_attacks,
            'is_permanent': self.is_permanent,
            'country': self.country
        }


class FirewallRule(Base):
    """Reglas del firewall UFW"""
    __tablename__ = 'firewall_rules'

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_number = Column(Integer)
    action = Column(String, nullable=False, index=True)
    protocol = Column(String)
    port = Column(Integer)
    port_range = Column(String)
    source_ip = Column(String)
    destination_ip = Column(String)
    interface = Column(String)
    comment = Column(Text)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, default='system')
    modified_at = Column(DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'rule_number': self.rule_number,
            'action': self.action,
            'protocol': self.protocol,
            'port': self.port,
            'source_ip': self.source_ip,
            'is_active': self.is_active
        }


class Fail2banJail(Base):
    """Configuración de jails de Fail2ban"""
    __tablename__ = 'fail2ban_jails'

    id = Column(Integer, primary_key=True, autoincrement=True)
    jail_name = Column(String, unique=True, nullable=False, index=True)
    filter_name = Column(String, nullable=False)
    log_path = Column(String, nullable=False)
    port = Column(String)
    protocol = Column(String, default='tcp')
    max_retry = Column(Integer, default=5)
    find_time = Column(Integer, default=600)
    ban_time = Column(Integer, default=3600)
    is_enabled = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime)
    total_bans = Column(Integer, default=0)
    currently_banned = Column(Integer, default=0)
    config_json = Column(Text)

    def to_dict(self):
        return {
            'id': self.id,
            'jail_name': self.jail_name,
            'filter_name': self.filter_name,
            'log_path': self.log_path,
            'max_retry': self.max_retry,
            'find_time': self.find_time,
            'ban_time': self.ban_time,
            'is_enabled': self.is_enabled,
            'total_bans': self.total_bans,
            'currently_banned': self.currently_banned
        }


class Threat(Base):
    """Amenazas detectadas en el sistema"""
    __tablename__ = 'threats'

    id = Column(Integer, primary_key=True, autoincrement=True)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    threat_type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False)
    source = Column(String, nullable=False)
    target_path = Column(Text)
    process_name = Column(String)
    process_pid = Column(Integer)
    description = Column(Text, nullable=False)
    evidence = Column(Text)  # JSON
    is_resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime)
    resolved_by = Column(String)
    resolution_action = Column(String)
    false_positive = Column(Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'source': self.source,
            'description': self.description,
            'is_resolved': self.is_resolved
        }


class User(Base):
    """Usuarios del sistema"""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    email = Column(String)
    full_name = Column(String)
    role = Column(String, default='viewer')
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime)
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String)
    api_token = Column(String)

    sessions = relationship("ActiveSession", back_populates="user")
    logs = relationship("SystemLog", back_populates="user")

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class ActiveSession(Base):
    """Sesiones activas de usuarios"""
    __tablename__ = 'active_sessions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    session_token = Column(String, unique=True, nullable=False, index=True)
    ip_address = Column(String, nullable=False)
    user_agent = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_valid = Column(Boolean, default=True, index=True)

    user = relationship("User", back_populates="sessions")


class SystemLog(Base):
    """Logs del sistema de seguridad"""
    __tablename__ = 'system_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    log_level = Column(String, nullable=False, index=True)
    module = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    ip_address = Column(String)
    details = Column(Text)
    success = Column(Boolean, default=True)

    user = relationship("User", back_populates="logs")

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'log_level': self.log_level,
            'module': self.module,
            'action': self.action,
            'success': self.success,
            'details': self.details
        }


class SystemConfig(Base):
    """Configuración del sistema"""
    __tablename__ = 'system_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    config_key = Column(String, unique=True, nullable=False, index=True)
    config_value = Column(Text)
    config_type = Column(String, default='string')
    description = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow)
    updated_by = Column(String)


class Alert(Base):
    """Alertas y notificaciones"""
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    alert_type = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    source = Column(String)
    is_read = Column(Boolean, default=False, index=True)
    is_resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime)
    resolved_by = Column(String)
    action_taken = Column(Text)
    extra_info = Column(Text)  # JSON (renamed from metadata to avoid SQLAlchemy conflict)

    def to_dict(self):
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'message': self.message,
            'is_read': self.is_read,
            'is_resolved': self.is_resolved
        }


class IPWhitelist(Base):
    """IPs en whitelist (nunca bloquear)"""
    __tablename__ = 'ip_whitelist'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String, unique=True, nullable=False, index=True)
    ip_range = Column(String)
    description = Column(Text, nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)
    added_by = Column(String)
    is_active = Column(Boolean, default=True, index=True)
    never_block = Column(Boolean, default=True)


class IPBlacklist(Base):
    """IPs en blacklist permanente"""
    __tablename__ = 'ip_blacklist'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String, unique=True, nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    added_by = Column(String)
    reason = Column(Text, nullable=False)
    source = Column(String)
    threat_score = Column(Integer, default=100)
    is_active = Column(Boolean, default=True, index=True)
    extra_data = Column(Text)  # JSON (renamed from metadata to avoid SQLAlchemy conflict)


class HourlyStat(Base):
    """Estadísticas por hora"""
    __tablename__ = 'hourly_stats'

    id = Column(Integer, primary_key=True, autoincrement=True)
    hour_timestamp = Column(DateTime, nullable=False, index=True)
    total_requests = Column(Integer, default=0)
    blocked_requests = Column(Integer, default=0)
    unique_ips = Column(Integer, default=0)
    attacks_detected = Column(Integer, default=0)
    attacks_by_type = Column(Text)  # JSON
    top_countries = Column(Text)  # JSON
    bandwidth_used = Column(Integer, default=0)


class MonitoredPort(Base):
    """Puertos monitoreados"""
    __tablename__ = 'monitored_ports'

    id = Column(Integer, primary_key=True, autoincrement=True)
    port_number = Column(Integer, nullable=False, index=True)
    protocol = Column(String, default='tcp')
    service_name = Column(String)
    expected_state = Column(String, default='closed')
    current_state = Column(String)
    last_checked = Column(DateTime)
    alert_on_change = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True, index=True)


# Función para inicializar la base de datos
def init_database():
    """Crear todas las tablas si no existen"""
    engine = create_engine(DATABASE_URL, echo=False)
    Base.metadata.create_all(engine)
    return engine


# Función para obtener sesión de base de datos
def get_session():
    """Obtener sesión de SQLAlchemy"""
    engine = create_engine(DATABASE_URL, echo=False)
    Session = sessionmaker(bind=engine)
    return Session()


# Función para insertar configuración por defecto
def insert_default_config():
    """Insertar configuración por defecto"""
    session = get_session()

    default_configs = [
        ('auto_block_threshold', '10', 'int', 'Número de ataques antes de bloqueo automático'),
        ('alert_email', '', 'string', 'Email para alertas de seguridad'),
        ('alert_enabled', 'true', 'bool', 'Activar alertas por email'),
        ('geo_blocking_enabled', 'false', 'bool', 'Bloquear países específicos'),
        ('blocked_countries', '[]', 'json', 'Lista de países bloqueados'),
        ('max_requests_per_minute', '100', 'int', 'Límite de peticiones por minuto'),
        ('ssh_max_attempts', '5', 'int', 'Intentos SSH permitidos'),
        ('auto_update_security', 'true', 'bool', 'Auto-instalar actualizaciones de seguridad'),
        ('retention_days', '90', 'int', 'Días de retención de logs'),
        ('threat_intel_enabled', 'false', 'bool', 'Usar threat intelligence feeds'),
    ]

    for key, value, type_, desc in default_configs:
        existing = session.query(SystemConfig).filter_by(config_key=key).first()
        if not existing:
            config = SystemConfig(
                config_key=key,
                config_value=value,
                config_type=type_,
                description=desc
            )
            session.add(config)

    session.commit()
    session.close()
