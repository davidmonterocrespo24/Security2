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


class GeoConfig(Base):
    """Configuración de filtrado geográfico"""
    __tablename__ = 'geo_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    enabled = Column(Boolean, default=False, index=True)
    mode = Column(String, default='whitelist')  # 'whitelist' o 'blacklist'
    countries = Column(Text)  # JSON: lista de códigos ISO de países
    block_unknown = Column(Boolean, default=False)  # Bloquear IPs sin país identificado
    updated_at = Column(DateTime, default=datetime.utcnow)
    updated_by = Column(String)

    def to_dict(self):
        countries_list = []
        if self.countries:
            try:
                countries_list = json.loads(self.countries)
            except:
                countries_list = []

        return {
            'id': self.id,
            'enabled': self.enabled,
            'mode': self.mode,
            'countries': countries_list,
            'block_unknown': self.block_unknown,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by': self.updated_by
        }


class MLPrediction(Base):
    """Caché de predicciones ML para IPs"""
    __tablename__ = 'ml_predictions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String, nullable=False, index=True)
    analyzed_at = Column(DateTime, default=datetime.utcnow, index=True)
    ml_confidence = Column(Float, nullable=False, index=True)
    is_suspicious = Column(Boolean, default=False, index=True)
    is_anomaly = Column(Boolean, default=False)
    total_events = Column(Integer, default=0)
    suspicious_events = Column(Integer, default=0)
    anomaly_events = Column(Integer, default=0)
    country = Column(String)
    country_code = Column(String)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    reasons = Column(Text)  # Razones del modelo
    recommended_action = Column(String)  # block, monitor, ignore
    is_blocked = Column(Boolean, default=False)
    model_version = Column(String)  # Versión del modelo usado
    is_valid = Column(Boolean, default=True, index=True)  # False si necesita recalcular

    # Nuevos campos para mejoras ML
    threat_score = Column(Float, default=0.0, index=True)  # Threat Score 0-100
    action_text = Column(String)  # Texto de acción recomendada
    behavioral_features = Column(Text)  # JSON con features conductuales
    threat_factors = Column(Text)  # JSON con factores de amenaza
    requests_per_minute = Column(Float, default=0.0)
    error_ratio = Column(Float, default=0.0)
    is_bot = Column(Boolean, default=False)

    def to_dict(self):
        # Parse JSON fields
        behavioral_features_dict = {}
        threat_factors_list = []

        if self.behavioral_features:
            try:
                behavioral_features_dict = json.loads(self.behavioral_features)
            except:
                pass

        if self.threat_factors:
            try:
                threat_factors_list = json.loads(self.threat_factors)
            except:
                pass

        return {
            'ip_address': self.ip_address,
            'analyzed_at': self.analyzed_at.isoformat() if self.analyzed_at else None,
            'ml_confidence': self.ml_confidence,
            'is_suspicious': self.is_suspicious,
            'is_anomaly': self.is_anomaly,
            'total_events': self.total_events,
            'suspicious_events': self.suspicious_events,
            'anomaly_events': self.anomaly_events,
            'country': self.country,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'reasons': self.reasons,
            'recommended_action': self.recommended_action,
            'is_blocked': self.is_blocked,
            # Nuevos campos
            'threat_score': self.threat_score,
            'action_text': self.action_text,
            'behavioral_features': behavioral_features_dict,
            'threat_factors': threat_factors_list,
            'requests_per_minute': self.requests_per_minute,
            'error_ratio': self.error_ratio,
            'is_bot': self.is_bot
        }


# ============================================================================
# MODELOS DE ZEEK - Network Security Monitor Integration
# ============================================================================

class ZeekConnection(Base):
    """Conexiones de red capturadas por Zeek (conn.log)"""
    __tablename__ = 'zeek_connections'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    uid = Column(String, unique=True, index=True)  # Unique ID de Zeek

    # Direcciones y puertos
    source_ip = Column(String, nullable=False, index=True)
    source_port = Column(Integer)
    dest_ip = Column(String, nullable=False, index=True)
    dest_port = Column(Integer, index=True)

    # Protocolo y servicio
    protocol = Column(String, index=True)  # tcp, udp, icmp
    service = Column(String, index=True)   # http, ssh, dns, ssl, etc

    # Duración y bytes
    duration = Column(Float)
    orig_bytes = Column(Integer, default=0)
    resp_bytes = Column(Integer, default=0)

    # Estado de conexión
    conn_state = Column(String)  # S0, S1, SF, REJ, etc

    # Paquetes
    orig_pkts = Column(Integer, default=0)
    resp_pkts = Column(Integer, default=0)

    # Localización
    local_orig = Column(Boolean, default=False)
    local_resp = Column(Boolean, default=False)

    # Historia de conexión
    history = Column(String)

    # Análisis ML
    is_suspicious = Column(Boolean, default=False, index=True)
    ml_analyzed = Column(Boolean, default=False)
    threat_score = Column(Float)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'uid': self.uid,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'dest_ip': self.dest_ip,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'service': self.service,
            'duration': self.duration,
            'orig_bytes': self.orig_bytes,
            'resp_bytes': self.resp_bytes,
            'conn_state': self.conn_state,
            'is_suspicious': self.is_suspicious
        }


class ZeekDNS(Base):
    """Queries DNS capturadas por Zeek (dns.log)"""
    __tablename__ = 'zeek_dns'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    uid = Column(String, index=True)

    # IPs
    source_ip = Column(String, nullable=False, index=True)
    dest_ip = Column(String)

    # Query DNS
    query = Column(String, nullable=False, index=True)
    query_type = Column(String)  # A, AAAA, PTR, MX, etc
    query_class = Column(String)

    # Respuesta
    rcode = Column(Integer)  # Response code
    rcode_name = Column(String)  # NOERROR, NXDOMAIN, etc
    answers = Column(Text)  # JSON list de respuestas
    ttls = Column(Text)  # JSON list de TTLs

    # Flags
    AA = Column(Boolean, default=False)  # Authoritative Answer
    TC = Column(Boolean, default=False)  # Truncated
    RD = Column(Boolean, default=False)  # Recursion Desired
    RA = Column(Boolean, default=False)  # Recursion Available

    # Análisis
    is_suspicious = Column(Boolean, default=False, index=True)
    is_tunneling = Column(Boolean, default=False)  # DNS tunneling detected
    query_entropy = Column(Float)  # Entropía de query (DGA detection)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'query': self.query,
            'query_type': self.query_type,
            'rcode_name': self.rcode_name,
            'is_suspicious': self.is_suspicious,
            'is_tunneling': self.is_tunneling
        }


class ZeekSSL(Base):
    """Conexiones SSL/TLS capturadas por Zeek (ssl.log)"""
    __tablename__ = 'zeek_ssl'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    uid = Column(String, index=True)

    # IPs
    source_ip = Column(String, nullable=False, index=True)
    dest_ip = Column(String)
    dest_port = Column(Integer)

    # Versión SSL/TLS
    version = Column(String, index=True)  # TLSv1.2, TLSv1.3, etc

    # Cipher suite
    cipher = Column(String)
    curve = Column(String)

    # Certificado
    server_name = Column(String, index=True)  # SNI
    subject = Column(String)
    issuer = Column(String)

    # Validación
    validation_status = Column(String)

    # Certificado details
    cert_chain_fuids = Column(Text)  # File UIDs de certificados
    client_cert_chain_fuids = Column(Text)

    # Fechas del certificado
    not_valid_before = Column(DateTime)
    not_valid_after = Column(DateTime)

    # Análisis de seguridad
    is_self_signed = Column(Boolean, default=False, index=True)
    is_expired = Column(Boolean, default=False, index=True)
    is_weak_cipher = Column(Boolean, default=False)
    is_suspicious = Column(Boolean, default=False, index=True)

    # JA3 Fingerprint (opcional)
    ja3 = Column(String, index=True)
    ja3s = Column(String)  # Server JA3

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'version': self.version,
            'server_name': self.server_name,
            'is_self_signed': self.is_self_signed,
            'is_expired': self.is_expired,
            'is_suspicious': self.is_suspicious
        }


class ZeekHTTP(Base):
    """Tráfico HTTP capturado por Zeek (http.log)"""
    __tablename__ = 'zeek_http'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    uid = Column(String, index=True)

    # IPs
    source_ip = Column(String, nullable=False, index=True)
    dest_ip = Column(String)
    dest_port = Column(Integer)

    # Request
    method = Column(String, index=True)  # GET, POST, etc
    host = Column(String, index=True)
    uri = Column(Text)
    referrer = Column(Text)
    user_agent = Column(Text)

    # Response
    status_code = Column(Integer, index=True)
    status_msg = Column(String)

    # Tamaños
    request_body_len = Column(Integer, default=0)
    response_body_len = Column(Integer, default=0)

    # Content type
    resp_mime_types = Column(Text)  # JSON list

    # Tags de Zeek
    tags = Column(Text)  # JSON list de tags

    # Análisis
    is_suspicious = Column(Boolean, default=False, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'method': self.method,
            'host': self.host,
            'uri': self.uri,
            'status_code': self.status_code,
            'user_agent': self.user_agent,
            'is_suspicious': self.is_suspicious
        }


class ZeekFiles(Base):
    """Archivos detectados por Zeek (files.log)"""
    __tablename__ = 'zeek_files'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    fuid = Column(String, unique=True, index=True)  # File UID

    # Conexión relacionada
    conn_uids = Column(Text)  # JSON list de UIDs

    # IPs
    source_ip = Column(String, index=True)
    dest_ip = Column(String)

    # Archivo
    filename = Column(String)
    mime_type = Column(String, index=True)

    # Tamaño
    total_bytes = Column(Integer)
    seen_bytes = Column(Integer)
    missing_bytes = Column(Integer)

    # Hashes
    md5 = Column(String, index=True)
    sha1 = Column(String, index=True)
    sha256 = Column(String, index=True)

    # Protocolo de origen
    source_protocol = Column(String)  # HTTP, SMTP, FTP, etc

    # Análisis
    is_malware = Column(Boolean, default=False, index=True)
    is_suspicious = Column(Boolean, default=False, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'fuid': self.fuid,
            'source_ip': self.source_ip,
            'filename': self.filename,
            'mime_type': self.mime_type,
            'total_bytes': self.total_bytes,
            'md5': self.md5,
            'is_malware': self.is_malware
        }


class ZeekNotice(Base):
    """Alertas/Notices generadas por Zeek (notice.log)"""
    __tablename__ = 'zeek_notices'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    uid = Column(String, index=True)

    # IPs involucradas
    source_ip = Column(String, index=True)
    dest_ip = Column(String)
    dest_port = Column(Integer)

    # Notice
    note = Column(String, nullable=False, index=True)  # Tipo de notice
    msg = Column(Text, nullable=False)  # Mensaje
    sub = Column(Text)  # Sub-mensaje

    # Protocolo
    protocol = Column(String)

    # Acciones tomadas
    actions = Column(Text)  # JSON list de acciones

    # Severidad (custom)
    severity = Column(String, default='medium', index=True)

    # Archivo relacionado
    file_mime_type = Column(String)
    file_desc = Column(String)

    # Supresión
    suppress_for = Column(Float)  # Tiempo de supresión en segundos

    # Estado
    is_resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'note': self.note,
            'msg': self.msg,
            'severity': self.severity,
            'is_resolved': self.is_resolved
        }


class ZeekConfig(Base):
    """Configuración de Zeek"""
    __tablename__ = 'zeek_config'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Estado de instalación
    is_installed = Column(Boolean, default=False)
    zeek_version = Column(String)
    install_path = Column(String)

    # Estado del servicio
    is_running = Column(Boolean, default=False)
    last_started = Column(DateTime)
    last_stopped = Column(DateTime)

    # Configuración de monitoreo
    monitored_interface = Column(String)  # eth0, ens33, etc
    log_dir = Column(String)  # Directorio de logs

    # Opciones de logs
    log_format = Column(String, default='json')  # json o ascii
    log_rotation_interval = Column(Integer, default=3600)  # segundos

    # Scripts habilitados
    enabled_scripts = Column(Text)  # JSON list de scripts

    # Importación automática
    auto_import_enabled = Column(Boolean, default=True)
    auto_import_interval = Column(Integer, default=300)  # segundos
    last_import = Column(DateTime)

    # Threat Intelligence
    intel_enabled = Column(Boolean, default=False)
    intel_sources = Column(Text)  # JSON list de fuentes

    # Actualización
    updated_at = Column(DateTime, default=datetime.utcnow)
    updated_by = Column(String)

    def to_dict(self):
        return {
            'id': self.id,
            'is_installed': self.is_installed,
            'zeek_version': self.zeek_version,
            'is_running': self.is_running,
            'monitored_interface': self.monitored_interface,
            'log_dir': self.log_dir,
            'auto_import_enabled': self.auto_import_enabled,
            'intel_enabled': self.intel_enabled
        }


class ZeekStats(Base):
    """Estadísticas agregadas de Zeek por hora"""
    __tablename__ = 'zeek_stats'

    id = Column(Integer, primary_key=True, autoincrement=True)
    hour_timestamp = Column(DateTime, nullable=False, index=True)

    # Conexiones
    total_connections = Column(Integer, default=0)
    unique_source_ips = Column(Integer, default=0)
    unique_dest_ips = Column(Integer, default=0)

    # Protocolos
    tcp_connections = Column(Integer, default=0)
    udp_connections = Column(Integer, default=0)
    icmp_connections = Column(Integer, default=0)

    # Servicios top
    top_services = Column(Text)  # JSON dict {service: count}

    # DNS
    dns_queries = Column(Integer, default=0)
    dns_nxdomain = Column(Integer, default=0)

    # SSL/TLS
    ssl_connections = Column(Integer, default=0)
    ssl_invalid_certs = Column(Integer, default=0)

    # HTTP
    http_requests = Column(Integer, default=0)
    http_errors = Column(Integer, default=0)

    # Archivos
    files_transferred = Column(Integer, default=0)

    # Alertas
    notices_generated = Column(Integer, default=0)

    # Tráfico
    total_bytes_sent = Column(Integer, default=0)
    total_bytes_received = Column(Integer, default=0)

    # Port scans detectados
    port_scans_detected = Column(Integer, default=0)

    def to_dict(self):
        return {
            'hour_timestamp': self.hour_timestamp.isoformat() if self.hour_timestamp else None,
            'total_connections': self.total_connections,
            'unique_source_ips': self.unique_source_ips,
            'dns_queries': self.dns_queries,
            'ssl_connections': self.ssl_connections,
            'http_requests': self.http_requests,
            'notices_generated': self.notices_generated,
            'port_scans_detected': self.port_scans_detected
        }


# ============================================================================
# SISTEMA DE ALERTAS Y NOTIFICACIONES
# ============================================================================

class AlertChannel(Base):
    """Canales de notificación (Email, Telegram, Slack, Discord, Webhook)"""
    __tablename__ = 'alert_channels'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Información básica
    channel_name = Column(String, unique=True, nullable=False, index=True)
    channel_type = Column(String, nullable=False, index=True)  # 'email', 'telegram', 'slack', 'discord', 'webhook'
    description = Column(Text)

    # Configuración (JSON)
    # Para email: {'smtp_server': '...', 'smtp_port': 587, 'smtp_user': '...', 'recipients': ['...']}
    # Para telegram: {'bot_token': '...', 'chat_id': '...'}
    # Para slack: {'webhook_url': '...'}
    # Para webhook: {'url': '...', 'method': 'POST', 'headers': {...}}
    config = Column(Text, nullable=False)  # JSON

    # Estado
    is_enabled = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)  # Verificado con mensaje de prueba
    last_test_at = Column(DateTime)
    last_test_success = Column(Boolean)

    # Estadísticas
    total_alerts_sent = Column(Integer, default=0)
    successful_sends = Column(Integer, default=0)
    failed_sends = Column(Integer, default=0)
    last_alert_sent_at = Column(DateTime)

    # Auditoría
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String)
    updated_at = Column(DateTime)
    updated_by = Column(String)

    def to_dict(self):
        # Parse config sin exponer credenciales sensibles
        config_dict = {}
        if self.config:
            try:
                config_dict = json.loads(self.config)
                # Ocultar credenciales
                if 'smtp_password' in config_dict:
                    config_dict['smtp_password'] = '***'
                if 'bot_token' in config_dict:
                    config_dict['bot_token'] = config_dict['bot_token'][:10] + '***'
            except:
                pass

        return {
            'id': self.id,
            'channel_name': self.channel_name,
            'channel_type': self.channel_type,
            'description': self.description,
            'config': config_dict,
            'is_enabled': self.is_enabled,
            'is_verified': self.is_verified,
            'total_alerts_sent': self.total_alerts_sent,
            'successful_sends': self.successful_sends,
            'failed_sends': self.failed_sends,
            'last_alert_sent_at': self.last_alert_sent_at.isoformat() if self.last_alert_sent_at else None
        }


class AlertRule(Base):
    """Reglas para disparar alertas automáticamente"""
    __tablename__ = 'alert_rules'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Información básica
    rule_name = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text)

    # Tipo de regla
    rule_type = Column(String, nullable=False, index=True)  # 'ml_prediction', 'zeek_detection', 'fail2ban_ban', 'custom'

    # Condiciones (JSON)
    # Ejemplos:
    # {'ml_confidence': {'operator': '>', 'value': 0.8}}
    # {'zeek_detection_type': {'operator': 'in', 'value': ['port_scan', 'dns_tunneling']}}
    # {'severity': {'operator': '==', 'value': 'CRITICAL'}}
    conditions = Column(Text, nullable=False)  # JSON

    # Umbral de severidad mínimo
    severity_threshold = Column(String, index=True)  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

    # Canales a utilizar (IDs de AlertChannel)
    channel_ids = Column(Text)  # JSON list de IDs

    # Configuración de envío
    is_enabled = Column(Boolean, default=True, index=True)
    cooldown_minutes = Column(Integer, default=0)  # Tiempo mínimo entre alertas del mismo tipo
    last_triggered_at = Column(DateTime)

    # Plantilla de mensaje
    message_template = Column(Text)  # Jinja2 template (opcional)
    subject_template = Column(String)  # Para emails

    # Estadísticas
    total_triggers = Column(Integer, default=0)
    total_alerts_sent = Column(Integer, default=0)
    last_error = Column(Text)

    # Auditoría
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String)
    updated_at = Column(DateTime)
    updated_by = Column(String)

    def to_dict(self):
        # Parse JSON fields
        conditions_dict = {}
        channel_ids_list = []

        if self.conditions:
            try:
                conditions_dict = json.loads(self.conditions)
            except:
                pass

        if self.channel_ids:
            try:
                channel_ids_list = json.loads(self.channel_ids)
            except:
                pass

        return {
            'id': self.id,
            'rule_name': self.rule_name,
            'description': self.description,
            'rule_type': self.rule_type,
            'conditions': conditions_dict,
            'severity_threshold': self.severity_threshold,
            'channel_ids': channel_ids_list,
            'is_enabled': self.is_enabled,
            'cooldown_minutes': self.cooldown_minutes,
            'last_triggered_at': self.last_triggered_at.isoformat() if self.last_triggered_at else None,
            'total_triggers': self.total_triggers,
            'total_alerts_sent': self.total_alerts_sent
        }


class AlertLog(Base):
    """Historial de alertas enviadas"""
    __tablename__ = 'alert_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Relaciones
    rule_id = Column(Integer, ForeignKey('alert_rules.id'), index=True)
    channel_id = Column(Integer, ForeignKey('alert_channels.id'), index=True)

    # Información de la alerta
    severity = Column(String, nullable=False, index=True)
    subject = Column(String)
    message = Column(Text, nullable=False)

    # Evento que disparó la alerta (JSON)
    # Contiene toda la información del evento (IP, tipo, score, etc)
    event_metadata = Column(Text)  # JSON

    # Envío
    sent_at = Column(DateTime, default=datetime.utcnow, index=True)
    success = Column(Boolean, default=False, index=True)
    error_message = Column(Text)

    # Respuesta (para webhooks)
    response_code = Column(Integer)
    response_body = Column(Text)

    # Tiempo de envío
    send_duration_ms = Column(Integer)  # Milisegundos

    def to_dict(self):
        # Parse metadata
        metadata_dict = {}
        if self.event_metadata:
            try:
                metadata_dict = json.loads(self.event_metadata)
            except:
                pass

        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'channel_id': self.channel_id,
            'severity': self.severity,
            'subject': self.subject,
            'message': self.message,
            'event_metadata': metadata_dict,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'success': self.success,
            'error_message': self.error_message,
            'response_code': self.response_code,
            'send_duration_ms': self.send_duration_ms
        }


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


# ============================================================================
# SISTEMA DE TAREAS PROGRAMADAS (CRON JOBS)
# ============================================================================

class ScheduledTask(Base):
    """Tareas programadas (cron jobs) gestionadas desde el panel web"""
    __tablename__ = 'scheduled_tasks'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Información básica
    task_name = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text)

    # Tipo de tarea
    task_type = Column(String, nullable=False, index=True)  # 'zeek_import', 'ml_analysis', 'cleanup', 'custom'

    # Función a ejecutar
    module_name = Column(String, nullable=False)  # 'modules.zeek_analyzer'
    function_name = Column(String, nullable=False)  # 'import_zeek_logs_to_db'
    function_params = Column(Text)  # JSON con parámetros

    # Programación (formato cron)
    schedule_type = Column(String, nullable=False, default='interval')  # 'interval', 'cron', 'daily', 'hourly'
    interval_minutes = Column(Integer)  # Para schedule_type='interval'
    cron_expression = Column(String)  # Para schedule_type='cron' (ej: '0 */6 * * *')
    hour = Column(Integer)  # Para schedule_type='daily' (0-23)
    minute = Column(Integer, default=0)  # Minuto específico

    # Estado
    is_enabled = Column(Boolean, default=True, index=True)
    is_running = Column(Boolean, default=False, index=True)

    # Ejecución
    last_run = Column(DateTime)
    last_run_status = Column(String)  # 'success', 'error', 'running'
    last_run_message = Column(Text)
    last_run_duration = Column(Float)  # Segundos

    next_run = Column(DateTime, index=True)

    # Estadísticas
    total_runs = Column(Integer, default=0)
    successful_runs = Column(Integer, default=0)
    failed_runs = Column(Integer, default=0)

    # Configuración avanzada
    timeout_seconds = Column(Integer, default=300)  # Timeout de ejecución
    retry_on_failure = Column(Boolean, default=False)
    max_retries = Column(Integer, default=3)

    # Alertas
    alert_on_failure = Column(Boolean, default=True)
    alert_email = Column(String)

    # Auditoría
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String)
    updated_at = Column(DateTime)
    updated_by = Column(String)

    def to_dict(self):
        return {
            'id': self.id,
            'task_name': self.task_name,
            'description': self.description,
            'task_type': self.task_type,
            'module_name': self.module_name,
            'function_name': self.function_name,
            'schedule_type': self.schedule_type,
            'interval_minutes': self.interval_minutes,
            'cron_expression': self.cron_expression,
            'hour': self.hour,
            'minute': self.minute,
            'is_enabled': self.is_enabled,
            'is_running': self.is_running,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'last_run_status': self.last_run_status,
            'last_run_message': self.last_run_message,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'total_runs': self.total_runs,
            'successful_runs': self.successful_runs,
            'failed_runs': self.failed_runs
        }


class TaskLog(Base):
    """Historial de ejecución de tareas programadas"""
    __tablename__ = 'task_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, ForeignKey('scheduled_tasks.id'), nullable=False, index=True)

    # Ejecución
    started_at = Column(DateTime, nullable=False, index=True)
    finished_at = Column(DateTime)
    duration = Column(Float)  # Segundos

    # Resultado
    status = Column(String, nullable=False, index=True)  # 'success', 'error', 'timeout'
    message = Column(Text)
    error_details = Column(Text)  # Stacktrace si hubo error

    # Output de la tarea
    output = Column(Text)  # JSON con resultados

    # Métricas
    records_processed = Column(Integer)
    records_created = Column(Integer)
    records_updated = Column(Integer)
    records_deleted = Column(Integer)

    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'finished_at': self.finished_at.isoformat() if self.finished_at else None,
            'duration': self.duration,
            'status': self.status,
            'message': self.message,
            'records_processed': self.records_processed
        }


# ============================================================================
# SISTEMA DE AUTO-BLOQUEO BASADO EN ML
# ============================================================================

class AutoBlockPolicy(Base):
    """Políticas de auto-bloqueo basadas en ML"""
    __tablename__ = 'auto_block_policies'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Información básica
    policy_name = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text)

    # Estado
    enabled = Column(Boolean, default=False, index=True)

    # Criterios de bloqueo
    min_ml_confidence = Column(Float, default=85.0)  # % mínimo de confianza ML
    min_threat_score = Column(Float, default=70.0)   # Threat score mínimo
    min_severity = Column(String, default='high')    # 'low', 'medium', 'high', 'critical'
    min_events = Column(Integer, default=3)          # Mínimo de eventos detectados

    # Requerimientos adicionales
    require_multiple_sources = Column(Boolean, default=True)  # Requerir 2+ fuentes (ML, Zeek, Fail2ban)

    # Configuración de bloqueo
    default_block_duration = Column(Integer, default=24)  # Horas
    permanent_block = Column(Boolean, default=False)      # Bloqueo permanente
    apply_to_fail2ban = Column(Boolean, default=True)     # Aplicar también en Fail2ban

    # Excepciones
    whitelist_enabled = Column(Boolean, default=True)    # Respetar whitelist
    exclude_internal_ips = Column(Boolean, default=True)  # No bloquear IPs internas

    # Estadísticas
    total_blocks = Column(Integer, default=0)
    last_block_at = Column(DateTime)

    # Auditoría
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String)
    updated_at = Column(DateTime)
    updated_by = Column(String)

    def to_dict(self):
        return {
            'id': self.id,
            'policy_name': self.policy_name,
            'description': self.description,
            'enabled': self.enabled,
            'min_ml_confidence': self.min_ml_confidence,
            'min_threat_score': self.min_threat_score,
            'min_severity': self.min_severity,
            'min_events': self.min_events,
            'require_multiple_sources': self.require_multiple_sources,
            'default_block_duration': self.default_block_duration,
            'permanent_block': self.permanent_block,
            'apply_to_fail2ban': self.apply_to_fail2ban,
            'whitelist_enabled': self.whitelist_enabled,
            'exclude_internal_ips': self.exclude_internal_ips,
            'total_blocks': self.total_blocks,
            'last_block_at': self.last_block_at.isoformat() if self.last_block_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


# ============================================================================
# MÉTRICAS DEL MODELO ML
# ============================================================================

class MLModelMetrics(Base):
    """Métricas y evaluación del modelo de Machine Learning"""
    __tablename__ = 'ml_model_metrics'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Versión del modelo
    model_version = Column(String, nullable=False, index=True)

    # Timestamp de evaluación
    evaluated_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Métricas de clasificación
    accuracy = Column(Float, nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    f1_score = Column(Float, nullable=False)
    roc_auc = Column(Float)

    # Datos de evaluación
    samples_evaluated = Column(Integer, default=0)

    # Matriz de confusión (JSON)
    confusion_matrix = Column(Text)  # [[tn, fp], [fn, tp]]

    # Curvas (JSON)
    roc_curve_data = Column(Text)  # {fpr: [], tpr: [], thresholds: []}
    pr_curve_data = Column(Text)   # {precision: [], recall: [], thresholds: []}

    # Metadata adicional (JSON)
    extra_data = Column(Text)  # Información extra, feature importance, etc.

    def to_dict(self):
        # Parse JSON fields
        cm = []
        roc = {}
        pr = {}
        meta = {}

        if self.confusion_matrix:
            try:
                cm = json.loads(self.confusion_matrix)
            except:
                pass

        if self.roc_curve_data:
            try:
                roc = json.loads(self.roc_curve_data)
            except:
                pass

        if self.pr_curve_data:
            try:
                pr = json.loads(self.pr_curve_data)
            except:
                pass

        if self.extra_data:
            try:
                meta = json.loads(self.extra_data)
            except:
                pass

        return {
            'id': self.id,
            'model_version': self.model_version,
            'evaluated_at': self.evaluated_at.isoformat() if self.evaluated_at else None,
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'roc_auc': self.roc_auc,
            'samples_evaluated': self.samples_evaluated,
            'confusion_matrix': cm,
            'roc_curve_data': roc,
            'pr_curve_data': pr,
            'extra_data': meta
        }
