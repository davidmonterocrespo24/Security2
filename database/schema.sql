-- Sistema de Seguridad para Ubuntu Server
-- Base de datos SQLite para gestión completa de seguridad

-- Tabla de eventos de seguridad
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL, -- 'ssh_attack', 'http_flood', 'port_scan', 'bot_detected', 'brute_force', 'sql_injection', 'xss_attempt', 'ddos', 'malware', 'intrusion'
    severity TEXT NOT NULL, -- 'low', 'medium', 'high', 'critical'
    source_ip TEXT NOT NULL,
    target_port INTEGER,
    protocol TEXT, -- 'ssh', 'http', 'https', 'ftp', 'sftp', 'smtp', 'other'
    attack_vector TEXT, -- 'password_guess', 'credential_stuffing', 'directory_traversal', 'command_injection', etc.
    details TEXT,
    user_agent TEXT,
    request_path TEXT,
    payload TEXT,
    geo_location TEXT,
    is_blocked BOOLEAN DEFAULT 0,
    blocked_by TEXT, -- 'fail2ban', 'firewall', 'manual', 'auto'
    false_positive BOOLEAN DEFAULT 0,
    INDEXED(timestamp),
    INDEXED(source_ip),
    INDEXED(event_type),
    INDEXED(severity)
);

-- Tabla de IPs bloqueadas
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    first_blocked DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_blocked DATETIME DEFAULT CURRENT_TIMESTAMP,
    blocked_by TEXT NOT NULL, -- 'fail2ban', 'firewall', 'manual', 'auto_detection'
    jail_name TEXT,
    reason TEXT NOT NULL,
    threat_level TEXT DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    total_attacks INTEGER DEFAULT 1,
    attack_types TEXT, -- JSON array de tipos de ataques
    is_permanent BOOLEAN DEFAULT 0,
    unblock_time DATETIME,
    unblocked_at DATETIME,
    unblocked_by TEXT,
    notes TEXT,
    country TEXT,
    asn TEXT,
    INDEXED(ip_address),
    INDEXED(is_permanent),
    INDEXED(threat_level)
);

-- Tabla de reglas de firewall
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_number INTEGER,
    action TEXT NOT NULL, -- 'allow', 'deny', 'reject', 'limit'
    protocol TEXT, -- 'tcp', 'udp', 'icmp', 'any'
    port INTEGER,
    port_range TEXT, -- '8000:9000'
    source_ip TEXT,
    destination_ip TEXT,
    interface TEXT,
    comment TEXT,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT DEFAULT 'system',
    modified_at DATETIME,
    INDEXED(is_active),
    INDEXED(action)
);

-- Tabla de jails de Fail2ban
CREATE TABLE IF NOT EXISTS fail2ban_jails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jail_name TEXT UNIQUE NOT NULL,
    filter_name TEXT NOT NULL,
    log_path TEXT NOT NULL,
    port TEXT,
    protocol TEXT DEFAULT 'tcp',
    max_retry INTEGER DEFAULT 5,
    find_time INTEGER DEFAULT 600,
    ban_time INTEGER DEFAULT 3600,
    is_enabled BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    total_bans INTEGER DEFAULT 0,
    currently_banned INTEGER DEFAULT 0,
    config_json TEXT, -- Configuración adicional en JSON
    INDEXED(jail_name),
    INDEXED(is_enabled)
);

-- Tabla de amenazas detectadas
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_type TEXT NOT NULL, -- 'malware', 'backdoor', 'rootkit', 'trojan', 'suspicious_file', 'suspicious_process', 'privilege_escalation'
    severity TEXT NOT NULL,
    source TEXT NOT NULL, -- 'file_system', 'process', 'network', 'log_analysis'
    target_path TEXT,
    process_name TEXT,
    process_pid INTEGER,
    description TEXT NOT NULL,
    evidence TEXT, -- JSON con detalles técnicos
    is_resolved BOOLEAN DEFAULT 0,
    resolved_at DATETIME,
    resolved_by TEXT,
    resolution_action TEXT, -- 'quarantine', 'delete', 'ignore', 'monitor'
    false_positive BOOLEAN DEFAULT 0,
    INDEXED(detected_at),
    INDEXED(threat_type),
    INDEXED(is_resolved)
);

-- Tabla de usuarios y autenticación
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    full_name TEXT,
    role TEXT DEFAULT 'viewer', -- 'admin', 'operator', 'viewer'
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    failed_login_attempts INTEGER DEFAULT 0,
    last_failed_login DATETIME,
    two_factor_enabled BOOLEAN DEFAULT 0,
    two_factor_secret TEXT,
    api_token TEXT,
    INDEXED(username),
    INDEXED(is_active)
);

-- Tabla de sesiones activas
CREATE TABLE IF NOT EXISTS active_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    is_valid BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEXED(session_token),
    INDEXED(user_id),
    INDEXED(is_valid)
);

-- Tabla de logs del sistema
CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    log_level TEXT NOT NULL, -- 'debug', 'info', 'warning', 'error', 'critical'
    module TEXT NOT NULL, -- 'fail2ban', 'firewall', 'scanner', 'auth', etc.
    action TEXT NOT NULL,
    user_id INTEGER,
    ip_address TEXT,
    details TEXT,
    success BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEXED(timestamp),
    INDEXED(log_level),
    INDEXED(module)
);

-- Tabla de configuración del sistema
CREATE TABLE IF NOT EXISTS system_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key TEXT UNIQUE NOT NULL,
    config_value TEXT,
    config_type TEXT DEFAULT 'string', -- 'string', 'int', 'bool', 'json'
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    INDEXED(config_key)
);

-- Tabla de alertas y notificaciones
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_type TEXT NOT NULL, -- 'security_breach', 'high_threat', 'system_down', 'disk_full', 'suspicious_activity'
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    source TEXT, -- IP, proceso, archivo, etc.
    is_read BOOLEAN DEFAULT 0,
    is_resolved BOOLEAN DEFAULT 0,
    resolved_at DATETIME,
    resolved_by TEXT,
    action_taken TEXT,
    metadata TEXT, -- JSON con datos adicionales
    INDEXED(created_at),
    INDEXED(is_read),
    INDEXED(is_resolved),
    INDEXED(severity)
);

-- Tabla de análisis de logs
CREATE TABLE IF NOT EXISTS log_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    log_source TEXT NOT NULL, -- 'ssh', 'nginx_access', 'nginx_error', 'auth', 'syslog'
    log_file TEXT NOT NULL,
    total_lines INTEGER DEFAULT 0,
    suspicious_lines INTEGER DEFAULT 0,
    attack_patterns_found TEXT, -- JSON array
    top_attackers TEXT, -- JSON array
    summary TEXT,
    INDEXED(analyzed_at),
    INDEXED(log_source)
);

-- Tabla de whitelist (IPs permitidas)
CREATE TABLE IF NOT EXISTS ip_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    ip_range TEXT, -- CIDR notation
    description TEXT NOT NULL,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    added_by TEXT,
    is_active BOOLEAN DEFAULT 1,
    never_block BOOLEAN DEFAULT 1,
    INDEXED(ip_address),
    INDEXED(is_active)
);

-- Tabla de blacklist permanente
CREATE TABLE IF NOT EXISTS ip_blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    added_by TEXT,
    reason TEXT NOT NULL,
    source TEXT, -- 'manual', 'threat_intel', 'auto_detected', 'known_attacker'
    threat_score INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT 1,
    metadata TEXT, -- JSON
    INDEXED(ip_address),
    INDEXED(is_active)
);

-- Tabla de estadísticas por hora
CREATE TABLE IF NOT EXISTS hourly_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hour_timestamp DATETIME NOT NULL,
    total_requests INTEGER DEFAULT 0,
    blocked_requests INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    attacks_detected INTEGER DEFAULT 0,
    attacks_by_type TEXT, -- JSON
    top_countries TEXT, -- JSON
    bandwidth_used INTEGER DEFAULT 0,
    INDEXED(hour_timestamp)
);

-- Tabla de puertos monitoreados
CREATE TABLE IF NOT EXISTS monitored_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port_number INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service_name TEXT,
    expected_state TEXT DEFAULT 'closed', -- 'open', 'closed', 'filtered'
    current_state TEXT,
    last_checked DATETIME,
    alert_on_change BOOLEAN DEFAULT 1,
    is_active BOOLEAN DEFAULT 1,
    INDEXED(port_number),
    INDEXED(is_active)
);

-- Tabla de procesos sospechosos
CREATE TABLE IF NOT EXISTS suspicious_processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    process_name TEXT NOT NULL,
    pid INTEGER NOT NULL,
    user TEXT,
    command_line TEXT,
    cpu_usage REAL,
    memory_usage REAL,
    connections TEXT, -- JSON array de conexiones de red
    reason TEXT NOT NULL,
    is_terminated BOOLEAN DEFAULT 0,
    terminated_at DATETIME,
    INDEXED(detected_at),
    INDEXED(is_terminated)
);

-- Tabla de actualizaciones del sistema
CREATE TABLE IF NOT EXISTS system_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    package_name TEXT NOT NULL,
    current_version TEXT,
    available_version TEXT,
    is_security_update BOOLEAN DEFAULT 0,
    is_installed BOOLEAN DEFAULT 0,
    installed_at DATETIME,
    INDEXED(is_security_update),
    INDEXED(is_installed)
);

-- Insertar configuración por defecto
INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description) VALUES
('auto_block_threshold', '10', 'int', 'Número de ataques antes de bloqueo automático'),
('alert_email', '', 'string', 'Email para alertas de seguridad'),
('alert_enabled', 'true', 'bool', 'Activar alertas por email'),
('geo_blocking_enabled', 'false', 'bool', 'Bloquear países específicos'),
('blocked_countries', '[]', 'json', 'Lista de países bloqueados'),
('max_requests_per_minute', '100', 'int', 'Límite de peticiones por minuto'),
('ssh_max_attempts', '5', 'int', 'Intentos SSH permitidos'),
('auto_update_security', 'true', 'bool', 'Auto-instalar actualizaciones de seguridad'),
('retention_days', '90', 'int', 'Días de retención de logs'),
('threat_intel_enabled', 'false', 'bool', 'Usar threat intelligence feeds');

-- Crear índices adicionales para optimización
CREATE INDEX IF NOT EXISTS idx_events_ip_time ON security_events(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_blocked_ip_time ON blocked_ips(ip_address, first_blocked);
CREATE INDEX IF NOT EXISTS idx_threats_unresolved ON threats(is_resolved, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_unread ON alerts(is_read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_time_level ON system_logs(timestamp DESC, log_level);

-- Vistas útiles
CREATE VIEW IF NOT EXISTS active_threats AS
SELECT
    t.id,
    t.detected_at,
    t.threat_type,
    t.severity,
    t.description,
    t.target_path,
    t.process_name
FROM threats t
WHERE t.is_resolved = 0 AND t.false_positive = 0
ORDER BY t.detected_at DESC;

CREATE VIEW IF NOT EXISTS recent_attacks AS
SELECT
    se.id,
    se.timestamp,
    se.event_type,
    se.severity,
    se.source_ip,
    se.protocol,
    se.attack_vector,
    bi.country
FROM security_events se
LEFT JOIN blocked_ips bi ON se.source_ip = bi.ip_address
WHERE se.timestamp > datetime('now', '-24 hours')
ORDER BY se.timestamp DESC;

CREATE VIEW IF NOT EXISTS top_attackers AS
SELECT
    source_ip,
    COUNT(*) as attack_count,
    COUNT(DISTINCT event_type) as attack_types,
    MAX(timestamp) as last_attack,
    MAX(severity) as max_severity,
    GROUP_CONCAT(DISTINCT event_type) as attack_methods
FROM security_events
WHERE timestamp > datetime('now', '-7 days')
GROUP BY source_ip
ORDER BY attack_count DESC
LIMIT 100;

CREATE VIEW IF NOT EXISTS security_dashboard AS
SELECT
    (SELECT COUNT(*) FROM security_events WHERE timestamp > datetime('now', '-24 hours')) as attacks_today,
    (SELECT COUNT(*) FROM blocked_ips WHERE is_permanent = 0) as temp_blocked_ips,
    (SELECT COUNT(*) FROM blocked_ips WHERE is_permanent = 1) as perm_blocked_ips,
    (SELECT COUNT(*) FROM threats WHERE is_resolved = 0) as active_threats,
    (SELECT COUNT(*) FROM alerts WHERE is_resolved = 0) as pending_alerts,
    (SELECT COUNT(DISTINCT source_ip) FROM security_events WHERE timestamp > datetime('now', '-1 hour')) as active_attackers;
