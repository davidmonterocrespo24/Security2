# Plan de Integración: Zeek + Sistema ML de Seguridad

## 🎯 Objetivo
Integrar Zeek Network Security Monitor al sistema de seguridad existente, permitiendo gestión completa desde la interfaz web y alimentando el modelo ML con datos de red profundos.

---

## 📋 TAREAS DE IMPLEMENTACIÓN

### ✅ FASE 1: Infraestructura Base (Tareas 1-2)

#### ✅ Tarea 1: Documento de Planificación
- [x] Crear este documento con todas las tareas
- [x] Definir arquitectura de integración
- [x] Establecer alcance y objetivos

#### ⏳ Tarea 2: Modelos de Base de Datos
**Archivo:** `database/models.py`
- [ ] Crear tabla `ZeekConnection` (conn.log)
- [ ] Crear tabla `ZeekDNS` (dns.log)
- [ ] Crear tabla `ZeekSSL` (ssl.log)
- [ ] Crear tabla `ZeekHTTP` (http.log)
- [ ] Crear tabla `ZeekFiles` (files.log)
- [ ] Crear tabla `ZeekNotice` (notice.log - alertas)
- [ ] Crear tabla `ZeekConfig` (configuración de Zeek)
- [ ] Crear tabla `ZeekStats` (estadísticas agregadas)

---

### 🔧 FASE 2: Módulos Core (Tareas 3-5)

#### ⏳ Tarea 3: Módulo ZeekManager
**Archivo:** `modules/zeek_manager.py`
- [ ] Función: `check_zeek_installed()`
- [ ] Función: `install_zeek()` - Instalación desde repos oficiales
- [ ] Función: `get_zeek_status()` - Estado del servicio
- [ ] Función: `start_zeek()` - Iniciar servicio
- [ ] Función: `stop_zeek()` - Detener servicio
- [ ] Función: `restart_zeek()` - Reiniciar servicio
- [ ] Función: `get_zeek_version()` - Obtener versión
- [ ] Función: `get_interfaces()` - Listar interfaces de red
- [ ] Función: `configure_zeek(interface, options)` - Configurar Zeek
- [ ] Función: `get_log_files()` - Listar logs disponibles
- [ ] Función: `deploy_zeek_scripts()` - Desplegar scripts personalizados

#### ⏳ Tarea 4: Módulo ZeekAnalyzer
**Archivo:** `modules/zeek_analyzer.py`
- [ ] Clase: `ZeekLogParser` - Parser de logs JSON de Zeek
- [ ] Función: `parse_conn_log()` - Parsear conn.log
- [ ] Función: `parse_dns_log()` - Parsear dns.log
- [ ] Función: `parse_ssl_log()` - Parsear ssl.log
- [ ] Función: `parse_http_log()` - Parsear http.log
- [ ] Función: `parse_notice_log()` - Parsear notice.log (alertas)
- [ ] Función: `import_zeek_logs_to_db()` - Importar logs a BD
- [ ] Función: `detect_port_scan()` - Detectar escaneos de puertos
- [ ] Función: `detect_dns_tunneling()` - Detectar DNS tunneling
- [ ] Función: `analyze_ssl_certs()` - Analizar certificados SSL
- [ ] Función: `get_top_connections()` - Top conexiones
- [ ] Función: `get_suspicious_connections()` - Conexiones sospechosas

#### ⏳ Tarea 5: Integración con ML
**Archivo:** `modules/ml_detector.py` (actualizar)
- [ ] Agregar features de Zeek a `extract_features()`:
  - [ ] `connection_count` - Número de conexiones
  - [ ] `dns_requests_count` - Queries DNS
  - [ ] `port_scan_detected` - Escaneo detectado
  - [ ] `ssl_invalid_cert` - Certificado inválido
  - [ ] `unusual_protocol` - Protocolo inusual
  - [ ] `bytes_sent` - Bytes enviados
  - [ ] `bytes_received` - Bytes recibidos
  - [ ] `connection_duration` - Duración de conexión
  - [ ] `dns_query_entropy` - Entropía de queries DNS
  - [ ] `multiple_protocols` - Uso de múltiples protocolos
- [ ] Actualizar `prepare_training_data()` con datos de Zeek
- [ ] Crear función `enrich_event_with_zeek_data()`

---

### 🌐 FASE 3: Backend Web (Tarea 6)

#### ⏳ Tarea 6: Rutas Flask
**Archivo:** `app.py` (actualizar)
- [ ] Ruta: `GET /zeek/status` - Estado de Zeek
- [ ] Ruta: `POST /zeek/install` - Instalar Zeek
- [ ] Ruta: `POST /zeek/start` - Iniciar Zeek
- [ ] Ruta: `POST /zeek/stop` - Detener Zeek
- [ ] Ruta: `POST /zeek/restart` - Reiniciar Zeek
- [ ] Ruta: `GET /zeek/config` - Obtener configuración
- [ ] Ruta: `POST /zeek/config` - Actualizar configuración
- [ ] Ruta: `GET /zeek/logs` - Listar tipos de logs
- [ ] Ruta: `GET /zeek/logs/<tipo>` - Ver log específico
- [ ] Ruta: `POST /zeek/logs/import` - Importar logs a BD
- [ ] Ruta: `GET /zeek/stats` - Estadísticas generales
- [ ] Ruta: `GET /zeek/connections` - Ver conexiones
- [ ] Ruta: `GET /zeek/dns` - Ver queries DNS
- [ ] Ruta: `GET /zeek/ssl` - Ver conexiones SSL
- [ ] Ruta: `GET /zeek/notices` - Ver alertas de Zeek
- [ ] Ruta: `GET /zeek/port-scans` - Detectar port scans
- [ ] Ruta: `POST /zeek/ml-analyze` - Analizar con ML

---

### 🎨 FASE 4: Frontend Web (Tareas 7-10)

#### ⏳ Tarea 7: Página de Instalación
**Archivo:** `templates/zeek_install.html`
- [ ] Formulario de instalación
- [ ] Selección de interfaz de red
- [ ] Configuración básica (opciones de monitoreo)
- [ ] Barra de progreso de instalación
- [ ] Logs en tiempo real durante instalación

#### ⏳ Tarea 8: Página de Visualización de Logs
**Archivo:** `templates/zeek_logs.html`
- [ ] Tabs para diferentes tipos de logs:
  - [ ] Conexiones (conn.log)
  - [ ] DNS (dns.log)
  - [ ] SSL/TLS (ssl.log)
  - [ ] HTTP (http.log)
  - [ ] Alertas (notice.log)
- [ ] Tabla con paginación y filtros
- [ ] Búsqueda por IP, puerto, protocolo
- [ ] Exportar logs (CSV, JSON)
- [ ] Visualización en tiempo real (WebSocket opcional)

#### ⏳ Tarea 9: Página de Configuración
**Archivo:** `templates/zeek_config.html`
- [ ] Configuración de interfaz de red
- [ ] Activar/desactivar scripts de Zeek
- [ ] Configuración de logs (rotación, formato)
- [ ] Integración con threat intelligence
- [ ] Configuración de alertas
- [ ] Botones: Start, Stop, Restart, Reload Config

#### ⏳ Tarea 10: Dashboard de Estadísticas
**Archivo:** `templates/zeek_dashboard.html`
- [ ] Estadísticas en tiempo real:
  - [ ] Total de conexiones
  - [ ] Protocolos más usados (gráfico de pastel)
  - [ ] Top 10 IPs origen/destino
  - [ ] Top 10 puertos
  - [ ] Timeline de conexiones (gráfico de línea)
  - [ ] Alertas recientes
  - [ ] Port scans detectados
  - [ ] DNS queries sospechosas
  - [ ] Certificados SSL inválidos
- [ ] Tarjetas con métricas clave
- [ ] Integración con ML (IPs sospechosas desde Zeek)

---

### 🤖 FASE 5: Análisis Avanzado (Tareas 11-14)

#### ⏳ Tarea 11: Sistema de Importación Automática
**Archivo:** `modules/zeek_importer.py`
- [ ] Clase `ZeekAutoImporter`
- [ ] Monitoreo de directorio de logs de Zeek
- [ ] Importación automática cada N minutos
- [ ] Cola de procesamiento de logs
- [ ] Deduplicación de eventos
- [ ] Integración con ML automática

#### ⏳ Tarea 12: Detección de Port Scans
**Archivo:** `modules/zeek_detections.py`
- [ ] Función: `detect_port_scan_from_conn_log()`
- [ ] Algoritmo: Detectar > N puertos en < X segundos
- [ ] Crear alerta automática
- [ ] Bloqueo automático opcional
- [ ] Registrar en tabla `Threat`

#### ⏳ Tarea 13: Análisis de Tráfico DNS
**Archivo:** `modules/zeek_detections.py`
- [ ] Función: `analyze_dns_queries()`
- [ ] Detectar DNS tunneling (queries largas, alta entropía)
- [ ] Detectar DGA (Domain Generation Algorithm)
- [ ] Detectar queries a dominios maliciosos
- [ ] Integración con threat intelligence

#### ⏳ Tarea 14: Análisis SSL/TLS
**Archivo:** `modules/zeek_detections.py`
- [ ] Función: `analyze_ssl_connections()`
- [ ] Detectar certificados auto-firmados
- [ ] Detectar certificados expirados
- [ ] Detectar versiones SSL/TLS obsoletas
- [ ] Fingerprinting de JA3 (opcional)

---

### 🔔 FASE 6: Alertas y Automatización (Tarea 15)

#### ⏳ Tarea 15: Sistema de Alertas
**Archivo:** `modules/zeek_alerts.py`
- [ ] Función: `process_zeek_notice()`
- [ ] Crear alerta en tabla `Alert`
- [ ] Enviar notificación (email, Telegram, Slack)
- [ ] Acciones automáticas:
  - [ ] Bloquear IP si port scan
  - [ ] Bloquear IP si malware detected
  - [ ] Rate limiting si flood
- [ ] Dashboard de alertas en tiempo real

---

### 📚 FASE 7: Documentación (Tarea 16)

#### ⏳ Tarea 16: Documentación Completa
**Archivos a crear:**
- [ ] `ZEEK_INSTALLATION.md` - Guía de instalación
- [ ] `ZEEK_CONFIGURATION.md` - Guía de configuración
- [ ] `ZEEK_LOGS_GUIDE.md` - Guía de logs
- [ ] `ZEEK_ML_INTEGRATION.md` - Cómo funciona la integración ML
- [ ] `ZEEK_API.md` - Documentación de API REST
- [ ] Actualizar `README.md` con sección de Zeek
- [ ] Screenshots del panel web

---

## 🏗️ Arquitectura Propuesta

```
┌─────────────────────────────────────────────────────────────┐
│                        SISTEMA WEB                           │
│                       (Flask + HTML)                         │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │           PANEL WEB DE ZEEK                        │    │
│  │  - Instalación                                     │    │
│  │  - Configuración                                   │    │
│  │  - Visualización de Logs                           │    │
│  │  - Dashboard                                       │    │
│  │  - Alertas                                         │    │
│  └───────────────┬────────────────────────────────────┘    │
│                  │                                          │
│                  ▼                                          │
│  ┌────────────────────────────────────────────────────┐    │
│  │          MÓDULOS BACKEND                           │    │
│  │                                                     │    │
│  │  ┌───────────────┐  ┌────────────────┐            │    │
│  │  │ ZeekManager   │  │ ZeekAnalyzer   │            │    │
│  │  │ - Install     │  │ - Parse Logs   │            │    │
│  │  │ - Start/Stop  │  │ - Detect Scan  │            │    │
│  │  │ - Configure   │  │ - Analyze DNS  │            │    │
│  │  └───────┬───────┘  └────────┬───────┘            │    │
│  │          │                    │                     │    │
│  │          └──────────┬─────────┘                     │    │
│  │                     │                               │    │
│  │                     ▼                               │    │
│  │          ┌──────────────────────┐                  │    │
│  │          │  MLTrafficDetector   │                  │    │
│  │          │  (ML Engine)         │                  │    │
│  │          │  + Zeek Features     │                  │    │
│  │          └──────────┬───────────┘                  │    │
│  │                     │                               │    │
│  └─────────────────────┼───────────────────────────────┘    │
│                        │                                    │
│                        ▼                                    │
│  ┌────────────────────────────────────────────────────┐    │
│  │              BASE DE DATOS (SQLite)                │    │
│  │  - SecurityEvent                                   │    │
│  │  - BlockedIP                                       │    │
│  │  - MLPrediction                                    │    │
│  │  - ZeekConnection ← NUEVO                          │    │
│  │  - ZeekDNS ← NUEVO                                 │    │
│  │  - ZeekSSL ← NUEVO                                 │    │
│  │  - ZeekNotice ← NUEVO                              │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │
                              │ Logs JSON
                              │
                ┌─────────────┴──────────────┐
                │          ZEEK              │
                │   Network Security Monitor  │
                │                            │
                │  - conn.log (conexiones)   │
                │  - dns.log (DNS)           │
                │  - ssl.log (SSL/TLS)       │
                │  - http.log (HTTP)         │
                │  - notice.log (alertas)    │
                └────────────────────────────┘
                              ▲
                              │
                              │ Tráfico de Red
                              │
                ┌─────────────┴──────────────┐
                │    INTERFAZ DE RED (eth0)  │
                │    Todo el tráfico del VPS │
                └────────────────────────────┘
```

---

## 📦 Dependencias Adicionales

```bash
# Sistema
apt-get install zeek

# Python (agregar a requirements.txt)
pip install pyzmq  # Para comunicación con Zeek (opcional)
```

---

## 🔐 Consideraciones de Seguridad

1. **Permisos**: Zeek requiere acceso raw socket (root o capabilities)
2. **Privacidad**: Zeek captura TODO el tráfico de red
3. **Espacio en disco**: Los logs de Zeek pueden crecer rápidamente
4. **Rotación de logs**: Implementar rotación automática
5. **Rendimiento**: Monitorear uso de CPU/RAM

---

## 📊 Métricas de Éxito

- ✅ Instalación de Zeek desde panel web
- ✅ Visualización de todos los logs de Zeek
- ✅ Detección automática de port scans
- ✅ Análisis DNS integrado
- ✅ ML entrenado con datos de Zeek
- ✅ Bloqueos automáticos basados en Zeek + ML
- ✅ Dashboard en tiempo real

---

## 🚀 Orden de Implementación

1. **Primero**: Tareas 1-2 (Base de Datos)
2. **Segundo**: Tarea 3 (ZeekManager - instalación)
3. **Tercero**: Tarea 4 (ZeekAnalyzer - parseo)
4. **Cuarto**: Tarea 6 (Rutas Flask)
5. **Quinto**: Tareas 7-10 (Frontend)
6. **Sexto**: Tarea 5 (Integración ML)
7. **Séptimo**: Tareas 11-15 (Detecciones avanzadas)
8. **Octavo**: Tarea 16 (Documentación)

---

**Fecha de inicio:** 2025-11-17
**Estimado:** 16 tareas principales
**Estado actual:** Iniciando Fase 1

