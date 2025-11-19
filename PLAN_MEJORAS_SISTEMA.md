# Plan de Implementación - Mejoras del Sistema de Seguridad

**Fecha:** 2025-11-19
**Sistema:** VPS Security System (ML + Zeek + Fail2ban)
**Objetivo:** Mejorar funcionalidades de monitoreo, automatización y respuesta a amenazas

---

## Índice

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Funcionalidades Identificadas](#funcionalidades-identificadas)
3. [Plan de Implementación por Fases](#plan-de-implementación-por-fases)
4. [Fase 1: Alertas y Notificaciones](#fase-1-alertas-y-notificaciones-crítica)
5. [Fase 2: Dashboard Integrado Zeek + ML](#fase-2-dashboard-integrado-zeek--ml-crítica)
6. [Fase 3: Auto-Bloqueo Basado en ML](#fase-3-auto-bloqueo-basado-en-ml-crítica)
7. [Fase 4: Métricas del Modelo ML](#fase-4-métricas-del-modelo-ml-crítica)
8. [Fase 5: Sistema de Reportes](#fase-5-sistema-de-reportes-alta)
9. [Fase 6: Estadísticas de Fail2ban](#fase-6-estadísticas-de-fail2ban-alta)
10. [Fase 7: Integración Fail2ban + ML](#fase-7-integración-fail2ban--ml-alta)
11. [Fase 8: Búsqueda Avanzada de Logs Zeek](#fase-8-búsqueda-avanzada-de-logs-zeek-media)
12. [Fase 9: Logs de Auditoría](#fase-9-logs-de-auditoría-media)
13. [Fase 10: Playbooks de Respuesta](#fase-10-playbooks-de-respuesta-media)
14. [Cronograma General](#cronograma-general)
15. [Recursos Necesarios](#recursos-necesarios)
16. [Riesgos y Mitigación](#riesgos-y-mitigación)

---

## Resumen Ejecutivo

### Estado Actual del Sistema

El sistema de seguridad VPS cuenta con:
- ✅ **Machine Learning** funcional (33 features, 100% accuracy)
- ✅ **Zeek Network Monitor** instalado y capturando tráfico
- ✅ **Fail2ban** protegiendo servicios
- ✅ **Integración Zeek → ML** completada (18 features de red)
- ✅ **Tareas programadas** automatizadas desde web

### Gaps Identificados

Se identificaron **10 funcionalidades críticas faltantes** que limitan:
- 🔴 **Respuesta proactiva** - No hay alertas automáticas
- 🔴 **Visibilidad** - Datos aislados entre Zeek/ML/Fail2ban
- 🔴 **Automatización** - Auto-bloqueo solo parcial
- 🔴 **Auditoría** - No hay reportes ni logs de auditoría

### Objetivo del Plan

Implementar 10 mejoras en **3 meses** (12 semanas) organizadas en **4 prioridades**:
- 🔴 **Críticas** (4 funcionalidades) - Semanas 1-6
- 🟠 **Altas** (3 funcionalidades) - Semanas 7-9
- 🟡 **Medias** (3 funcionalidades) - Semanas 10-12

### Beneficios Esperados

1. **Reducción del 80% en tiempo de respuesta** (alertas automáticas)
2. **Visibilidad 360°** de amenazas (dashboard unificado)
3. **Automatización del 70% de bloqueos** (ML auto-block)
4. **Cumplimiento de auditoría** (reportes y logs)

---

## Funcionalidades Identificadas

### 🔴 Prioridad CRÍTICA (Implementar primero)

| # | Funcionalidad | Impacto | Tiempo Estimado | Complejidad |
|---|--------------|---------|-----------------|-------------|
| 1 | Sistema de Alertas y Notificaciones | MUY ALTO | 2 semanas | MEDIA |
| 2 | Dashboard Integrado Zeek + ML | ALTO | 2 semanas | ALTA |
| 3 | Auto-Bloqueo Basado en ML | ALTO | 1 semana | BAJA |
| 4 | Panel de Métricas del Modelo ML | ALTO | 1 semana | MEDIA |

**Total Fase Crítica: 6 semanas**

### 🟠 Prioridad ALTA (Implementar después)

| # | Funcionalidad | Impacto | Tiempo Estimado | Complejidad |
|---|--------------|---------|-----------------|-------------|
| 5 | Sistema de Reportes Automáticos | ALTO | 1.5 semanas | MEDIA |
| 6 | Estadísticas de Fail2ban | MEDIO | 1 semana | BAJA |
| 7 | Integración Fail2ban + ML | ALTO | 0.5 semanas | BAJA |

**Total Fase Alta: 3 semanas**

### 🟡 Prioridad MEDIA (Implementar al final)

| # | Funcionalidad | Impacto | Tiempo Estimado | Complejidad |
|---|--------------|---------|-----------------|-------------|
| 8 | Búsqueda Avanzada de Logs Zeek | MEDIO | 1 semana | MEDIA |
| 9 | Logs de Auditoría | MEDIO | 1 semana | MEDIA |
| 10 | Playbooks de Respuesta | MEDIO | 1 semana | ALTA |

**Total Fase Media: 3 semanas**

---

## Plan de Implementación por Fases

### Metodología

- **Desarrollo iterativo** - Cada fase entrega funcionalidad usable
- **Testing continuo** - Pruebas en servidor de desarrollo antes de producción
- **Rollback plan** - Git tags y backups de DB antes de cada deploy
- **Documentación** - Manual de usuario por funcionalidad

### Criterios de Éxito por Fase

Cada fase debe cumplir:
1. ✅ Código implementado y testeado
2. ✅ Base de datos migrada (si aplica)
3. ✅ Interfaz web funcional
4. ✅ API endpoints documentados
5. ✅ Tareas programadas configuradas (si aplica)
6. ✅ Manual de usuario creado
7. ✅ Testing en producción sin errores

---

## Fase 1: Alertas y Notificaciones (CRÍTICA)

**Duración:** 2 semanas
**Prioridad:** 🔴 CRÍTICA
**Semanas:** 1-2

### Objetivo

Implementar sistema completo de alertas para notificar automáticamente cuando:
- ML detecta IP sospechosa (confidence > 80%)
- Zeek detecta port scan, DNS tunneling, beaconing
- Fail2ban banea IPs de países específicos
- Múltiples eventos críticos en corto tiempo

### Componentes a Desarrollar

#### 1.1. Modelo de Base de Datos

**Archivo:** `database/models.py`

```python
class AlertChannel(Base):
    """Canales de notificación (Email, Telegram, Slack, Discord)"""
    id, channel_type (email/telegram/slack/discord/webhook)
    name, config (JSON), is_enabled, created_at, updated_at

class AlertRule(Base):
    """Reglas para disparar alertas"""
    id, rule_name, rule_type (ml_prediction/zeek_detection/fail2ban_ban/custom)
    conditions (JSON), severity_threshold, channel_ids (JSON)
    is_enabled, cooldown_minutes, created_at, updated_at

class AlertLog(Base):
    """Historial de alertas enviadas"""
    id, rule_id, channel_id, severity, message, metadata (JSON)
    sent_at, success, error_message
```

#### 1.2. Módulo de Alertas

**Archivo:** `modules/alert_manager.py` (NUEVO - ~500 líneas)

**Funcionalidades:**
- `send_email(to, subject, body)` - SMTP con Gmail/SendGrid
- `send_telegram(chat_id, message)` - Bot API
- `send_slack(webhook_url, message)` - Webhook
- `send_discord(webhook_url, embed)` - Webhook
- `evaluate_rule(rule, event)` - Evalúa si evento cumple regla
- `process_alert(event)` - Procesa evento y dispara alertas
- `format_alert_message(event, template)` - Formatea mensaje

**Dependencias:**
```bash
pip install python-telegram-bot aiosmtplib jinja2
```

#### 1.3. Integración con Sistemas Existentes

**Modificar:**
- `modules/ml_detector.py` - Llamar a `alert_manager.process_alert()` después de predicción
- `modules/zeek_ml_integration.py` - Alertar en `process_zeek_detections_to_events()`
- `modules/fail2ban_manager.py` - Alertar cuando se banea IP

**Ejemplo de integración:**
```python
# En ml_detector.py después de predecir
if prediction['is_malicious'] and prediction['confidence'] > 0.8:
    alert_manager.process_alert({
        'type': 'ml_prediction',
        'severity': 'HIGH',
        'ip': ip_address,
        'confidence': prediction['confidence'],
        'reason': prediction['reason']
    })
```

#### 1.4. API Endpoints

**Archivo:** `routes/alert_routes.py` (NUEVO - ~250 líneas)

```python
POST   /api/alerts/channels              # Crear canal
GET    /api/alerts/channels              # Listar canales
PUT    /api/alerts/channels/<id>         # Actualizar canal
DELETE /api/alerts/channels/<id>         # Eliminar canal
POST   /api/alerts/channels/<id>/test    # Enviar mensaje de prueba

POST   /api/alerts/rules                 # Crear regla
GET    /api/alerts/rules                 # Listar reglas
PUT    /api/alerts/rules/<id>            # Actualizar regla
DELETE /api/alerts/rules/<id>            # Eliminar regla
POST   /api/alerts/rules/<id>/toggle     # Activar/desactivar

GET    /api/alerts/logs                  # Historial de alertas
GET    /api/alerts/stats                 # Estadísticas (enviadas/fallidas)
```

#### 1.5. Interfaz Web

**Archivo:** `templates/alerts_config.html` (NUEVO - ~400 líneas)

**Secciones:**
1. **Canales de Notificación**
   - Formulario para agregar Email/Telegram/Slack/Discord
   - Lista de canales configurados
   - Botón "Enviar Prueba" para cada canal

2. **Reglas de Alerta**
   - Formulario con condiciones (ej: "ML confidence > 90%")
   - Selector de canales para cada regla
   - Configuración de cooldown (no spam)

3. **Historial de Alertas**
   - Tabla con alertas enviadas (últimas 100)
   - Filtros por severidad/canal/fecha
   - Gráfico de alertas por día

4. **Plantillas de Mensajes**
   - Editor de plantillas Jinja2 para personalizar mensajes
   - Variables disponibles: `{{ip}}`, `{{confidence}}`, `{{severity}}`, etc.

#### 1.6. Plantillas de Mensajes

**Archivo:** `templates/alert_templates/` (NUEVO)

```
ml_prediction.html         # Plantilla HTML para email (ML)
ml_prediction.txt          # Plantilla texto para Telegram (ML)
zeek_port_scan.html        # Port scan detectado
zeek_dns_tunneling.html    # DNS tunneling
fail2ban_ban.html          # IP baneada por Fail2ban
```

**Ejemplo de plantilla:**
```html
<!-- ml_prediction.html -->
<h2>🚨 Alerta de Seguridad - ML Detection</h2>
<p><strong>IP Sospechosa:</strong> {{ ip }}</p>
<p><strong>Confianza:</strong> {{ confidence }}%</p>
<p><strong>Razón:</strong> {{ reason }}</p>
<p><strong>País:</strong> {{ country }} ({{ flag }})</p>
<p><strong>Fecha:</strong> {{ timestamp }}</p>
<hr>
<p><a href="{{ dashboard_url }}">Ver en Dashboard</a></p>
```

#### 1.7. Configuración

**Archivo:** `.env` (agregar variables)

```bash
# Email (SMTP)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@tudominio.com
SMTP_PASSWORD=tu_password_app
ALERT_EMAIL_FROM=Security System <alerts@tudominio.com>
ALERT_EMAIL_TO=admin@tudominio.com

# Telegram
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=-1001234567890

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXX

# Discord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/123456/abcdef
```

### Tareas de Implementación - Semana 1

**Días 1-2: Base de Datos y Modelos**
- [ ] Crear modelos `AlertChannel`, `AlertRule`, `AlertLog`
- [ ] Migración de base de datos
- [ ] Seed data con reglas por defecto

**Días 3-5: Módulo de Alertas**
- [ ] Implementar `alert_manager.py`
- [ ] Integración con Email (SMTP)
- [ ] Integración con Telegram Bot
- [ ] Testing de envío de mensajes

### Tareas de Implementación - Semana 2

**Días 1-2: Integraciones**
- [ ] Modificar `ml_detector.py` para alertar
- [ ] Modificar `zeek_ml_integration.py` para alertar
- [ ] Modificar `fail2ban_manager.py` para alertar
- [ ] Testing de integración end-to-end

**Días 3-4: API y Frontend**
- [ ] Crear `alert_routes.py` con endpoints
- [ ] Crear `alerts_config.html` con formularios
- [ ] Agregar menú "Alertas" en sidebar
- [ ] Testing de UI

**Día 5: Testing y Deploy**
- [ ] Testing en servidor de desarrollo
- [ ] Documentación de usuario
- [ ] Deploy a producción
- [ ] Configurar alertas iniciales

### Entregables

1. ✅ Sistema de alertas multi-canal funcional
2. ✅ Interfaz web para configuración
3. ✅ 3 canales implementados (Email, Telegram, Webhook)
4. ✅ 5 reglas pre-configuradas (ML high confidence, Zeek detections, etc)
5. ✅ Historial de alertas con filtros
6. ✅ Manual de configuración

### Métricas de Éxito

- ✅ Alertas se envían en < 30 segundos desde detección
- ✅ Tasa de éxito de envío > 95%
- ✅ Cooldown funciona (no spam)
- ✅ Admin puede configurar canales sin código

---

## Fase 2: Dashboard Integrado Zeek + ML (CRÍTICA)

**Duración:** 2 semanas
**Prioridad:** 🔴 CRÍTICA
**Semanas:** 3-4

### Objetivo

Crear dashboard unificado que muestre:
- Top 10 IPs más peligrosas (combinando ML + Zeek + Fail2ban)
- Mapa de calor de amenazas por país
- Timeline de ataques en tiempo real
- Correlación entre detecciones de Zeek y predicciones ML
- Gráficos de tendencias (últimos 7/30 días)

### Componentes a Desarrollar

#### 2.1. Módulo de Análisis Integrado

**Archivo:** `modules/integrated_analyzer.py` (NUEVO - ~600 líneas)

**Funcionalidades:**
```python
def get_top_threats(hours_back=24, limit=10):
    """
    Combinar datos de Zeek, ML y Fail2ban para obtener IPs más peligrosas

    Score calculado como:
    - ML confidence (0-100)
    - Zeek detections count * 10
    - Fail2ban bans * 20
    - Events severity (CRITICAL=50, HIGH=30, MEDIUM=10, LOW=5)

    Returns:
        [{'ip': '1.2.3.4', 'score': 250, 'ml_confidence': 0.95,
          'zeek_detections': 5, 'fail2ban_bans': 2, 'country': 'CN', ...}]
    """

def get_threat_map(hours_back=24):
    """
    Mapa de amenazas por país (para visualización geográfica)

    Returns:
        {'CN': {'count': 45, 'avg_score': 75}, 'RU': {...}, ...}
    """

def get_attack_timeline(hours_back=24, interval_minutes=60):
    """
    Timeline de ataques agrupados por hora

    Returns:
        [{'hour': '2025-11-19 14:00', 'ml_detections': 5,
          'zeek_detections': 12, 'fail2ban_bans': 3}, ...]
    """

def get_correlation_matrix():
    """
    Matriz de correlación entre Zeek detections y ML predictions

    Returns:
        {'port_scan': {'ml_malicious': 0.85, 'ml_normal': 0.15},
         'dns_tunneling': {'ml_malicious': 0.92, 'ml_normal': 0.08}, ...}
    """

def get_threat_trends(days=7):
    """
    Tendencias de amenazas por día

    Returns:
        [{'date': '2025-11-19', 'total_threats': 123,
          'ml_detections': 45, 'zeek_detections': 67, 'fail2ban_bans': 11}, ...]
    """
```

#### 2.2. API Endpoints

**Archivo:** `routes/integrated_routes.py` (NUEVO - ~200 líneas)

```python
GET /api/integrated/top-threats?hours=24&limit=10
GET /api/integrated/threat-map?hours=24
GET /api/integrated/timeline?hours=24&interval=60
GET /api/integrated/correlation
GET /api/integrated/trends?days=7
GET /api/integrated/stats-summary            # Resumen de todas las stats
```

#### 2.3. Interfaz Web

**Archivo:** `templates/integrated_dashboard.html` (NUEVO - ~800 líneas)

**Layout:**

```
┌─────────────────────────────────────────────────────┐
│  RESUMEN GENERAL (4 cards)                          │
│  [Total Threats] [ML Detections] [Zeek] [Fail2ban] │
├─────────────────────────────────────────────────────┤
│  MAPA DE CALOR MUNDIAL           │  TOP 10 IPs     │
│  (Leaflet.js + Heatmap.js)       │  (tabla sorted) │
│                                   │                 │
├──────────────────────────────────┼─────────────────┤
│  TIMELINE DE ATAQUES (Chart.js - Line chart)       │
│  [ML | Zeek | Fail2ban por hora]                   │
├─────────────────────────────────────────────────────┤
│  CORRELACIÓN ZEEK ↔ ML           │  TENDENCIAS     │
│  (Heatmap matrix)                │  (últimos 7d)   │
└─────────────────────────────────────────────────────┘
```

**Tecnologías frontend:**
- **Chart.js** - Gráficos de líneas y barras
- **Leaflet.js** - Mapa mundial interactivo
- **DataTables.js** - Tablas sortables/filtrables
- **ApexCharts** - Heatmaps de correlación

#### 2.4. Bibliotecas JavaScript

Agregar a `templates/integrated_dashboard.html`:

```html
<!-- Chart.js para gráficos -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0"></script>

<!-- Leaflet para mapas -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<!-- DataTables para tablas interactivas -->
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.css" />
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.js"></script>

<!-- ApexCharts para heatmaps -->
<script src="https://cdn.jsdelivr.net/npm/apexcharts"></script>
```

#### 2.5. Componentes UI

**2.5.1. Cards de Resumen**

```html
<div class="grid grid-cols-4 gap-6 mb-6">
    <!-- Total Threats -->
    <div class="bg-gradient-to-br from-red-500 to-red-600 rounded-lg shadow p-6 text-white">
        <i class="fas fa-exclamation-triangle text-3xl mb-2"></i>
        <p class="text-sm opacity-80">Total Amenazas</p>
        <p id="total-threats" class="text-4xl font-bold">0</p>
        <p class="text-xs opacity-70">Últimas 24h</p>
    </div>

    <!-- ML Detections -->
    <div class="bg-gradient-to-br from-purple-500 to-purple-600 rounded-lg shadow p-6 text-white">
        <i class="fas fa-brain text-3xl mb-2"></i>
        <p class="text-sm opacity-80">ML Detections</p>
        <p id="ml-detections" class="text-4xl font-bold">0</p>
        <p class="text-xs opacity-70">Confidence > 80%</p>
    </div>

    <!-- Zeek Detections -->
    <div class="bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg shadow p-6 text-white">
        <i class="fas fa-network-wired text-3xl mb-2"></i>
        <p class="text-sm opacity-80">Zeek Detections</p>
        <p id="zeek-detections" class="text-4xl font-bold">0</p>
        <p class="text-xs opacity-70">Port scans, DNS, etc</p>
    </div>

    <!-- Fail2ban Bans -->
    <div class="bg-gradient-to-br from-orange-500 to-orange-600 rounded-lg shadow p-6 text-white">
        <i class="fas fa-ban text-3xl mb-2"></i>
        <p class="text-sm opacity-80">IPs Baneadas</p>
        <p id="fail2ban-bans" class="text-4xl font-bold">0</p>
        <p class="text-xs opacity-70">Fail2ban activas</p>
    </div>
</div>
```

**2.5.2. Mapa de Calor Mundial**

```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">
        <i class="fas fa-globe-americas mr-2"></i>
        Mapa de Amenazas por País
    </h3>
    <div id="threat-map" style="height: 400px;"></div>
</div>

<script>
// Inicializar mapa Leaflet
const map = L.map('threat-map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

// Cargar datos de amenazas
fetch('/api/integrated/threat-map?hours=24')
    .then(r => r.json())
    .then(data => {
        // Agregar marcadores con tamaño según cantidad de amenazas
        Object.entries(data).forEach(([country, stats]) => {
            const coords = getCountryCoords(country);
            const radius = Math.sqrt(stats.count) * 5;

            L.circle(coords, {
                color: 'red',
                fillColor: '#f03',
                fillOpacity: 0.5,
                radius: radius * 1000
            }).bindPopup(`
                <b>${country}</b><br>
                Amenazas: ${stats.count}<br>
                Score Promedio: ${stats.avg_score}
            `).addTo(map);
        });
    });
</script>
```

**2.5.3. Top 10 IPs Peligrosas**

```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">
        <i class="fas fa-skull-crossbones mr-2"></i>
        Top 10 IPs Más Peligrosas
    </h3>
    <table id="top-threats-table" class="w-full">
        <thead>
            <tr>
                <th>Rank</th>
                <th>IP</th>
                <th>País</th>
                <th>Score</th>
                <th>ML Conf.</th>
                <th>Zeek Det.</th>
                <th>F2B Bans</th>
                <th>Acciones</th>
            </tr>
        </thead>
        <tbody id="top-threats-body">
            <!-- Se llena dinámicamente -->
        </tbody>
    </table>
</div>

<script>
function loadTopThreats() {
    fetch('/api/integrated/top-threats?hours=24&limit=10')
        .then(r => r.json())
        .then(data => {
            const tbody = document.getElementById('top-threats-body');
            tbody.innerHTML = data.map((threat, idx) => `
                <tr class="${threat.score > 200 ? 'bg-red-50' : ''}">
                    <td class="font-bold">#${idx + 1}</td>
                    <td><code>${threat.ip}</code></td>
                    <td>${threat.country_flag} ${threat.country}</td>
                    <td>
                        <span class="px-2 py-1 rounded text-white ${
                            threat.score > 200 ? 'bg-red-600' :
                            threat.score > 100 ? 'bg-orange-600' : 'bg-yellow-600'
                        }">${threat.score}</span>
                    </td>
                    <td>${(threat.ml_confidence * 100).toFixed(0)}%</td>
                    <td>${threat.zeek_detections}</td>
                    <td>${threat.fail2ban_bans}</td>
                    <td>
                        <button onclick="blockIP('${threat.ip}')"
                                class="px-3 py-1 bg-red-600 text-white rounded text-xs">
                            <i class="fas fa-ban"></i> Bloquear
                        </button>
                        <a href="/ip-analysis?ip=${threat.ip}"
                           class="px-3 py-1 bg-blue-600 text-white rounded text-xs">
                            <i class="fas fa-search"></i> Analizar
                        </a>
                    </td>
                </tr>
            `).join('');

            // Inicializar DataTable
            $('#top-threats-table').DataTable({
                ordering: true,
                paging: false,
                searching: false
            });
        });
}
</script>
```

**2.5.4. Timeline de Ataques**

```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">
        <i class="fas fa-chart-line mr-2"></i>
        Timeline de Ataques (Últimas 24 horas)
    </h3>
    <canvas id="timeline-chart" height="80"></canvas>
</div>

<script>
fetch('/api/integrated/timeline?hours=24&interval=60')
    .then(r => r.json())
    .then(data => {
        const ctx = document.getElementById('timeline-chart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map(d => d.hour),
                datasets: [
                    {
                        label: 'ML Detections',
                        data: data.map(d => d.ml_detections),
                        borderColor: 'rgb(147, 51, 234)',
                        backgroundColor: 'rgba(147, 51, 234, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Zeek Detections',
                        data: data.map(d => d.zeek_detections),
                        borderColor: 'rgb(59, 130, 246)',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Fail2ban Bans',
                        data: data.map(d => d.fail2ban_bans),
                        borderColor: 'rgb(249, 115, 22)',
                        backgroundColor: 'rgba(249, 115, 22, 0.1)',
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top' }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    });
</script>
```

**2.5.5. Matriz de Correlación Zeek ↔ ML**

```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">
        <i class="fas fa-project-diagram mr-2"></i>
        Correlación Zeek Detections ↔ ML Predictions
    </h3>
    <div id="correlation-heatmap"></div>
</div>

<script>
fetch('/api/integrated/correlation')
    .then(r => r.json())
    .then(data => {
        const options = {
            series: [
                {
                    name: 'Port Scan',
                    data: [data.port_scan.ml_malicious * 100, data.port_scan.ml_normal * 100]
                },
                {
                    name: 'DNS Tunneling',
                    data: [data.dns_tunneling.ml_malicious * 100, data.dns_tunneling.ml_normal * 100]
                },
                {
                    name: 'Beaconing',
                    data: [data.beaconing.ml_malicious * 100, data.beaconing.ml_normal * 100]
                }
            ],
            chart: {
                type: 'heatmap',
                height: 250
            },
            plotOptions: {
                heatmap: {
                    colorScale: {
                        ranges: [
                            { from: 0, to: 30, color: '#00A100', name: 'low' },
                            { from: 31, to: 70, color: '#FFB200', name: 'medium' },
                            { from: 71, to: 100, color: '#FF0000', name: 'high' }
                        ]
                    }
                }
            },
            dataLabels: { enabled: true },
            xaxis: {
                categories: ['ML Malicious', 'ML Normal']
            }
        };

        const chart = new ApexCharts(document.querySelector("#correlation-heatmap"), options);
        chart.render();
    });
</script>
```

### Tareas de Implementación - Semana 3

**Días 1-2: Módulo de Análisis**
- [ ] Crear `integrated_analyzer.py`
- [ ] Implementar `get_top_threats()`
- [ ] Implementar `get_threat_map()`
- [ ] Implementar `get_attack_timeline()`
- [ ] Testing de queries de DB

**Días 3-5: API**
- [ ] Crear `integrated_routes.py`
- [ ] Implementar endpoints
- [ ] Optimizar queries (índices de DB)
- [ ] Testing de performance
- [ ] Documentar API

### Tareas de Implementación - Semana 4

**Días 1-3: Frontend**
- [ ] Crear `integrated_dashboard.html`
- [ ] Implementar cards de resumen
- [ ] Implementar mapa de calor (Leaflet.js)
- [ ] Implementar tabla Top 10 (DataTables.js)
- [ ] Implementar timeline (Chart.js)

**Días 4-5: Testing y Deploy**
- [ ] Implementar heatmap de correlación (ApexCharts)
- [ ] Agregar auto-refresh (cada 60 segundos)
- [ ] Testing de UI en diferentes navegadores
- [ ] Documentación de usuario
- [ ] Deploy a producción

### Entregables

1. ✅ Dashboard unificado funcional
2. ✅ 5 visualizaciones interactivas (mapa, tabla, timeline, heatmap, trends)
3. ✅ API con 6 endpoints optimizados
4. ✅ Auto-refresh cada 60 segundos
5. ✅ Responsive design (móvil/tablet/desktop)
6. ✅ Manual de usuario

### Métricas de Éxito

- ✅ Dashboard carga en < 3 segundos
- ✅ Datos se actualizan automáticamente
- ✅ Top 10 IPs muestra score correcto
- ✅ Mapa geográfico funciona en todos los navegadores
- ✅ Admin puede identificar amenazas en < 10 segundos

---

## Fase 3: Auto-Bloqueo Basado en ML (CRÍTICA)

**Duración:** 1 semana
**Prioridad:** 🔴 CRÍTICA
**Semanas:** 5

### Objetivo

Automatizar el bloqueo de IPs sospechosas basándose en predicciones ML con configuración desde web.

### Estado Actual

Ya existe auto-bloqueo parcial en [app.py:166-183](app.py#L166-L183) pero solo funciona para requests HTTP en tiempo real.

**Limitaciones actuales:**
- Solo bloquea durante requests activos
- No bloquea basándose en sugerencias ML batch
- No es configurable desde web
- No tiene auto-desbloqueo
- No registra acciones automáticas

### Componentes a Desarrollar

#### 3.1. Modelo de Base de Datos

**Archivo:** `database/models.py`

```python
class AutoBlockPolicy(Base):
    """Políticas de auto-bloqueo basadas en ML"""
    id, policy_name, is_enabled
    ml_confidence_threshold (float 0-1)
    zeek_detection_threshold (int)
    fail2ban_ban_threshold (int)
    auto_unblock_after_hours (int, nullable)
    block_method (firewall/fail2ban/both)
    whitelist_countries (JSON), blacklist_countries (JSON)
    created_at, updated_at

class AutoBlockLog(Base):
    """Historial de bloqueos automáticos"""
    id, policy_id, ip_address, country
    ml_confidence, zeek_detections, fail2ban_bans
    reason, blocked_at, unblocked_at
    block_method, was_auto_unblocked
```

#### 3.2. Módulo de Auto-Bloqueo

**Archivo:** `modules/auto_blocker.py` (NUEVO - ~400 líneas)

**Funcionalidades:**
```python
class AutoBlocker:
    def __init__(self, db_manager, firewall_manager, fail2ban_manager):
        pass

    def evaluate_ip(self, ip_address):
        """
        Evaluar si una IP debe ser bloqueada automáticamente

        Returns:
            {'should_block': True, 'policy': {...}, 'reason': '...', 'score': 250}
        """

    def block_ip(self, ip_address, policy, reason):
        """Bloquear IP según política (firewall/fail2ban/both)"""

    def unblock_ip(self, ip_address):
        """Desbloquear IP manualmente"""

    def process_batch(self, hours_back=1):
        """
        Procesar batch de IPs sospechosas desde sugerencias ML
        Ejecutar esta función cada 5 minutos desde TaskScheduler
        """

    def auto_unblock_expired(self):
        """
        Desbloquear IPs cuyo tiempo de bloqueo ha expirado
        Ejecutar cada hora
        """

    def is_whitelisted(self, ip_address, policy):
        """Verificar si IP está en whitelist o país permitido"""
```

#### 3.3. Integración con TaskScheduler

**Archivo:** `modules/task_scheduler.py` (modificar)

Agregar 2 tareas nuevas:
```python
# Tarea 4: Auto-bloqueo batch (cada 5 minutos)
{
    'task_name': 'Auto-Block Suspicious IPs',
    'task_type': 'auto_block_batch',
    'module_name': 'modules.auto_blocker',
    'function_name': 'process_batch',
    'schedule_type': 'interval',
    'interval_minutes': 5
}

# Tarea 5: Auto-desbloqueo expirados (cada hora)
{
    'task_name': 'Auto-Unblock Expired IPs',
    'task_type': 'auto_unblock',
    'module_name': 'modules.auto_blocker',
    'function_name': 'auto_unblock_expired',
    'schedule_type': 'interval',
    'interval_minutes': 60
}
```

#### 3.4. API Endpoints

**Archivo:** `routes/auto_block_routes.py` (NUEVO - ~150 líneas)

```python
GET    /api/auto-block/policies              # Listar políticas
POST   /api/auto-block/policies              # Crear política
PUT    /api/auto-block/policies/<id>         # Actualizar política
DELETE /api/auto-block/policies/<id>         # Eliminar política
POST   /api/auto-block/policies/<id>/toggle  # Activar/desactivar

GET    /api/auto-block/logs                  # Historial de bloqueos automáticos
POST   /api/auto-block/unblock/<ip>          # Desbloquear manualmente

GET    /api/auto-block/stats                 # Estadísticas (total bloqueados/desbloqueados)
POST   /api/auto-block/simulate              # Simular qué IPs se bloquearían (testing)
```

#### 3.5. Interfaz Web

**Archivo:** `templates/auto_block_config.html` (NUEVO - ~500 líneas)

**Secciones:**

**1. Políticas de Auto-Bloqueo**
```html
<div class="bg-white rounded-lg shadow p-6 mb-6">
    <h3 class="text-lg font-semibold mb-4">Políticas de Auto-Bloqueo</h3>

    <form id="policy-form">
        <div class="grid grid-cols-2 gap-4">
            <div>
                <label>Nombre de Política</label>
                <input type="text" name="policy_name" required>
            </div>

            <div>
                <label>Estado</label>
                <select name="is_enabled">
                    <option value="true">Activa</option>
                    <option value="false">Inactiva</option>
                </select>
            </div>

            <div>
                <label>ML Confidence Mínimo (%)</label>
                <input type="range" name="ml_confidence" min="50" max="100" value="80">
                <span id="confidence-value">80%</span>
            </div>

            <div>
                <label>Detecciones Zeek Mínimas</label>
                <input type="number" name="zeek_threshold" value="3" min="0">
            </div>

            <div>
                <label>Método de Bloqueo</label>
                <select name="block_method">
                    <option value="firewall">Firewall (UFW)</option>
                    <option value="fail2ban">Fail2ban</option>
                    <option value="both">Ambos</option>
                </select>
            </div>

            <div>
                <label>Auto-desbloquear después de (horas)</label>
                <input type="number" name="auto_unblock_hours" value="24" min="1">
                <small>Dejar vacío para bloqueo permanente</small>
            </div>

            <div>
                <label>Whitelist de Países (no bloquear)</label>
                <input type="text" name="whitelist_countries" placeholder="US,GB,DE">
            </div>

            <div>
                <label>Blacklist de Países (bloquear siempre)</label>
                <input type="text" name="blacklist_countries" placeholder="CN,RU,KP">
            </div>
        </div>

        <button type="submit" class="mt-4 px-6 py-2 bg-blue-600 text-white rounded">
            Guardar Política
        </button>

        <button type="button" onclick="simulatePolicy()" class="mt-4 px-6 py-2 bg-yellow-600 text-white rounded">
            <i class="fas fa-vial mr-2"></i>
            Simular (ver qué IPs se bloquearían)
        </button>
    </form>
</div>
```

**2. Políticas Activas**
```html
<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
    <!-- Se llenan dinámicamente las políticas creadas -->
    <div class="bg-white rounded-lg shadow p-6 border-l-4 border-green-500">
        <div class="flex justify-between items-start">
            <div>
                <h4 class="font-semibold">Política: High Confidence ML</h4>
                <p class="text-sm text-gray-600 mt-2">
                    <strong>Condiciones:</strong><br>
                    • ML Confidence > 85%<br>
                    • Zeek Detections > 2<br>
                    • Auto-desbloqueo: 24h
                </p>
            </div>
            <div>
                <span class="px-3 py-1 bg-green-500 text-white rounded text-xs">Activa</span>
            </div>
        </div>
        <div class="mt-4 flex space-x-2">
            <button onclick="togglePolicy(1)" class="px-3 py-1 bg-gray-600 text-white rounded text-sm">
                Pausar
            </button>
            <button onclick="editPolicy(1)" class="px-3 py-1 bg-blue-600 text-white rounded text-sm">
                Editar
            </button>
            <button onclick="deletePolicy(1)" class="px-3 py-1 bg-red-600 text-white rounded text-sm">
                Eliminar
            </button>
        </div>
    </div>
</div>
```

**3. Historial de Bloqueos Automáticos**
```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">Historial de Bloqueos Automáticos</h3>

    <table class="w-full">
        <thead>
            <tr>
                <th>Fecha</th>
                <th>IP</th>
                <th>País</th>
                <th>Política</th>
                <th>ML Conf.</th>
                <th>Zeek Det.</th>
                <th>Método</th>
                <th>Estado</th>
                <th>Acciones</th>
            </tr>
        </thead>
        <tbody id="auto-block-logs">
            <!-- Ejemplo de fila -->
            <tr>
                <td>2025-11-19 14:35</td>
                <td><code>45.142.212.61</code></td>
                <td>🇨🇳 CN</td>
                <td>High Confidence ML</td>
                <td><span class="px-2 py-1 bg-red-600 text-white rounded text-xs">92%</span></td>
                <td>5</td>
                <td>UFW + Fail2ban</td>
                <td><span class="px-2 py-1 bg-green-600 text-white rounded text-xs">Bloqueada</span></td>
                <td>
                    <button onclick="unblockIP('45.142.212.61')"
                            class="px-3 py-1 bg-orange-600 text-white rounded text-xs">
                        Desbloquear
                    </button>
                </td>
            </tr>
        </tbody>
    </table>
</div>
```

**4. Estadísticas de Auto-Bloqueo**
```html
<div class="grid grid-cols-4 gap-6 mt-6">
    <div class="bg-white rounded-lg shadow p-6 border-l-4 border-blue-500">
        <p class="text-sm text-gray-600">IPs Bloqueadas (24h)</p>
        <p id="blocked-24h" class="text-3xl font-bold">0</p>
    </div>

    <div class="bg-white rounded-lg shadow p-6 border-l-4 border-green-500">
        <p class="text-sm text-gray-600">Auto-Desbloqueadas (24h)</p>
        <p id="unblocked-24h" class="text-3xl font-bold">0</p>
    </div>

    <div class="bg-white rounded-lg shadow p-6 border-l-4 border-purple-500">
        <p class="text-sm text-gray-600">Actualmente Bloqueadas</p>
        <p id="currently-blocked" class="text-3xl font-bold">0</p>
    </div>

    <div class="bg-white rounded-lg shadow p-6 border-l-4 border-yellow-500">
        <p class="text-sm text-gray-600">Efectividad (%)</p>
        <p id="effectiveness" class="text-3xl font-bold">0%</p>
        <p class="text-xs text-gray-500">Reducción de ataques</p>
    </div>
</div>
```

**5. Simulador de Políticas**
```html
<!-- Modal que muestra qué IPs se bloquearían con la política actual -->
<div id="simulation-modal" class="hidden fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
    <div class="bg-white rounded-lg shadow-lg p-6 max-w-2xl w-full">
        <h3 class="text-lg font-semibold mb-4">Simulación de Política</h3>
        <p class="text-sm text-gray-600 mb-4">
            Las siguientes IPs serían bloqueadas si activas esta política ahora:
        </p>
        <table id="simulation-results" class="w-full mb-4">
            <!-- Resultados de simulación -->
        </table>
        <button onclick="closeSimulation()" class="px-4 py-2 bg-gray-600 text-white rounded">
            Cerrar
        </button>
    </div>
</div>
```

### Tareas de Implementación - Semana 5

**Días 1-2: Base de Datos y Módulo**
- [ ] Crear modelos `AutoBlockPolicy` y `AutoBlockLog`
- [ ] Migración de base de datos
- [ ] Implementar `auto_blocker.py`
- [ ] Testing de `evaluate_ip()` y `block_ip()`

**Día 3: Integración**
- [ ] Modificar `task_scheduler.py` para agregar 2 tareas nuevas
- [ ] Integrar con `firewall_manager.py` y `fail2ban_manager.py`
- [ ] Testing de bloqueo/desbloqueo

**Día 4: API y Frontend**
- [ ] Crear `auto_block_routes.py`
- [ ] Crear `auto_block_config.html`
- [ ] Agregar menú en sidebar

**Día 5: Testing y Deploy**
- [ ] Testing end-to-end con política de prueba
- [ ] Verificar auto-desbloqueo funciona
- [ ] Documentación de usuario
- [ ] Deploy a producción

### Entregables

1. ✅ Sistema de auto-bloqueo configurable desde web
2. ✅ Políticas con múltiples criterios (ML + Zeek + Fail2ban)
3. ✅ Auto-desbloqueo temporal
4. ✅ Simulador de políticas (testing seguro)
5. ✅ Historial completo de acciones automáticas
6. ✅ Whitelist/Blacklist por país
7. ✅ Manual de usuario

### Métricas de Éxito

- ✅ IPs maliciosas se bloquean en < 5 minutos
- ✅ Auto-desbloqueo funciona correctamente
- ✅ 0 falsos positivos en whitelist
- ✅ Admin puede configurar políticas sin código
- ✅ Simulador muestra resultados precisos

---

## Fase 4: Métricas del Modelo ML (CRÍTICA)

**Duración:** 1 semana
**Prioridad:** 🔴 CRÍTICA
**Semanas:** 6

### Objetivo

Crear dashboard de monitoreo para visualizar la salud y rendimiento del modelo ML en tiempo real.

### Componentes a Desarrollar

#### 4.1. Modelo de Base de Datos

**Archivo:** `database/models.py`

```python
class MLModelMetrics(Base):
    """Historial de métricas del modelo ML"""
    id, model_version (string)
    accuracy, precision, recall, f1_score
    training_samples, test_samples
    training_duration_seconds
    feature_count, feature_importance (JSON)
    confusion_matrix (JSON)
    trained_at, created_at

class MLPredictionMetrics(Base):
    """Métricas de predicciones en tiempo real (agregadas por hora)"""
    id, hour_timestamp
    total_predictions
    malicious_predictions, normal_predictions
    avg_confidence_malicious, avg_confidence_normal
    predictions_over_90_confidence, predictions_over_80_confidence
    created_at
```

#### 4.2. Actualizar ml_detector.py

**Archivo:** `modules/ml_detector.py` (modificar)

**Cambios:**
```python
def train_model(self):
    # ... código existente ...

    # NUEVO: Guardar métricas en DB
    from database.models import MLModelMetrics
    session = self.db.get_session()

    metrics = MLModelMetrics(
        model_version=f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        training_samples=len(X_train),
        test_samples=len(X_test),
        training_duration_seconds=training_duration,
        feature_count=len(feature_importances),
        feature_importance=dict(zip(feature_names, feature_importances)),
        confusion_matrix=confusion_matrix.tolist(),
        trained_at=datetime.utcnow()
    )
    session.add(metrics)
    session.commit()

def predict_ip(self, ip_address):
    # ... código existente ...

    # NUEVO: Registrar métrica de predicción (cada hora)
    self._log_prediction_metric(prediction)

    return prediction

def _log_prediction_metric(self, prediction):
    """Agregar predicción a métricas horarias"""
    from database.models import MLPredictionMetrics
    session = self.db.get_session()

    hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)

    # Buscar o crear registro de esta hora
    metric = session.query(MLPredictionMetrics).filter_by(
        hour_timestamp=hour
    ).first()

    if not metric:
        metric = MLPredictionMetrics(hour_timestamp=hour, total_predictions=0, ...)
        session.add(metric)

    # Actualizar contadores
    metric.total_predictions += 1
    if prediction['is_malicious']:
        metric.malicious_predictions += 1
        # Actualizar promedio de confidence...
    else:
        metric.normal_predictions += 1
        # ...

    session.commit()
```

#### 4.3. API Endpoints

**Archivo:** `routes/ml_metrics_routes.py` (NUEVO - ~200 líneas)

```python
GET /api/ml/metrics/latest                 # Últimas métricas del modelo
GET /api/ml/metrics/history?days=30        # Historial de entrenamientos
GET /api/ml/metrics/feature-importance     # Importancia de features actual
GET /api/ml/metrics/confusion-matrix       # Matriz de confusión actual

GET /api/ml/metrics/predictions/hourly?hours=24   # Predicciones por hora
GET /api/ml/metrics/predictions/summary           # Resumen de predicciones (24h)
GET /api/ml/metrics/predictions/distribution      # Distribución malicious vs normal

GET /api/ml/metrics/compare?v1=v1&v2=v2          # Comparar 2 versiones del modelo
```

#### 4.4. Interfaz Web

**Archivo:** `templates/ml_metrics.html` (NUEVO - ~700 líneas)

**Layout:**

```
┌──────────────────────────────────────────────────────┐
│  MÉTRICAS DEL MODELO (4 cards)                       │
│  [Accuracy] [Precision] [Recall] [F1-Score]          │
├──────────────────────────────────────────────────────┤
│  MATRIZ DE CONFUSIÓN    │  FEATURE IMPORTANCE        │
│  (Heatmap 2x2)          │  (Bar chart top 15)        │
├─────────────────────────┼────────────────────────────┤
│  HISTORIAL DE ACCURACY  │  INFO DEL MODELO           │
│  (Line chart últimos    │  • Versión: v20251119      │
│   10 entrenamientos)    │  • Entrenado: hace 2d      │
│                         │  • Samples: 888/222        │
│                         │  • Features: 33            │
├──────────────────────────────────────────────────────┤
│  PREDICCIONES EN TIEMPO REAL (Últimas 24h)          │
│  [Timeline: Malicious vs Normal por hora]            │
├──────────────────────────────────────────────────────┤
│  DISTRIBUCIÓN DE CONFIANZA                           │
│  [Donut chart: >90%, 80-90%, 70-80%, <70%]          │
└──────────────────────────────────────────────────────┘
```

**Código de componentes principales:**

**1. Cards de Métricas**
```html
<div class="grid grid-cols-4 gap-6 mb-6">
    <div class="bg-gradient-to-br from-green-500 to-green-600 rounded-lg shadow p-6 text-white">
        <i class="fas fa-check-circle text-3xl mb-2"></i>
        <p class="text-sm opacity-80">Accuracy</p>
        <p id="accuracy" class="text-4xl font-bold">0%</p>
        <p class="text-xs opacity-70">Último entrenamiento</p>
    </div>

    <div class="bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg shadow p-6 text-white">
        <i class="fas fa-bullseye text-3xl mb-2"></i>
        <p class="text-sm opacity-80">Precision</p>
        <p id="precision" class="text-4xl font-bold">0%</p>
    </div>

    <div class="bg-gradient-to-br from-purple-500 to-purple-600 rounded-lg shadow p-6 text-white">
        <i class="fas fa-filter text-3xl mb-2"></i>
        <p class="text-sm opacity-80">Recall</p>
        <p id="recall" class="text-4xl font-bold">0%</p>
    </div>

    <div class="bg-gradient-to-br from-orange-500 to-orange-600 rounded-lg shadow p-6 text-white">
        <i class="fas fa-chart-bar text-3xl mb-2"></i>
        <p class="text-sm opacity-80">F1-Score</p>
        <p id="f1-score" class="text-4xl font-bold">0%</p>
    </div>
</div>
```

**2. Matriz de Confusión**
```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">Matriz de Confusión</h3>
    <canvas id="confusion-matrix" width="300" height="300"></canvas>
</div>

<script>
fetch('/api/ml/metrics/confusion-matrix')
    .then(r => r.json())
    .then(data => {
        const ctx = document.getElementById('confusion-matrix').getContext('2d');

        // Dibujar matriz 2x2
        const matrix = data.confusion_matrix; // [[TN, FP], [FN, TP]]

        // Usar Chart.js con plugin de heatmap
        new Chart(ctx, {
            type: 'matrix',
            data: {
                datasets: [{
                    label: 'Confusion Matrix',
                    data: [
                        {x: 'Normal', y: 'Predicted Normal', v: matrix[0][0]},
                        {x: 'Malicious', y: 'Predicted Normal', v: matrix[0][1]},
                        {x: 'Normal', y: 'Predicted Malicious', v: matrix[1][0]},
                        {x: 'Malicious', y: 'Predicted Malicious', v: matrix[1][1]}
                    ],
                    backgroundColor(ctx) {
                        const value = ctx.dataset.data[ctx.dataIndex].v;
                        const max = Math.max(...matrix.flat());
                        const alpha = value / max;
                        return `rgba(59, 130, 246, ${alpha})`;
                    },
                    width: ({chart}) => (chart.chartArea || {}).width / 2 - 1,
                    height: ({chart}) => (chart.chartArea || {}).height / 2 - 1
                }]
            },
            options: {
                plugins: {
                    tooltip: {
                        callbacks: {
                            label(context) {
                                return context.dataset.data[context.dataIndex].v + ' predictions';
                            }
                        }
                    }
                }
            }
        });
    });
</script>
```

**3. Feature Importance (Top 15)**
```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">Importancia de Features (Top 15)</h3>
    <canvas id="feature-importance-chart" height="400"></canvas>
</div>

<script>
fetch('/api/ml/metrics/feature-importance')
    .then(r => r.json())
    .then(data => {
        const ctx = document.getElementById('feature-importance-chart').getContext('2d');

        // Ordenar por importancia y tomar top 15
        const sorted = Object.entries(data.feature_importance)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15);

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sorted.map(([name, _]) => name),
                datasets: [{
                    label: 'Importancia (%)',
                    data: sorted.map(([_, importance]) => (importance * 100).toFixed(2)),
                    backgroundColor: sorted.map((_, idx) => {
                        // Degradado de colores
                        if (idx < 5) return 'rgba(220, 38, 38, 0.8)'; // Rojo (más importantes)
                        if (idx < 10) return 'rgba(251, 146, 60, 0.8)'; // Naranja
                        return 'rgba(34, 197, 94, 0.8)'; // Verde
                    })
                }]
            },
            options: {
                indexAxis: 'y', // Barras horizontales
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { beginAtZero: true, max: 100 }
                }
            }
        });
    });
</script>
```

**4. Historial de Accuracy**
```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">Evolución del Accuracy</h3>
    <canvas id="accuracy-history-chart" height="250"></canvas>
</div>

<script>
fetch('/api/ml/metrics/history?days=30')
    .then(r => r.json())
    .then(data => {
        const ctx = document.getElementById('accuracy-history-chart').getContext('2d');

        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map(m => m.trained_at),
                datasets: [
                    {
                        label: 'Accuracy',
                        data: data.map(m => m.accuracy * 100),
                        borderColor: 'rgb(34, 197, 94)',
                        backgroundColor: 'rgba(34, 197, 94, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Precision',
                        data: data.map(m => m.precision * 100),
                        borderColor: 'rgb(59, 130, 246)',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Recall',
                        data: data.map(m => m.recall * 100),
                        borderColor: 'rgb(147, 51, 234)',
                        backgroundColor: 'rgba(147, 51, 234, 0.1)',
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, max: 100 }
                }
            }
        });
    });
</script>
```

**5. Predicciones en Tiempo Real (24h)**
```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">Predicciones en Tiempo Real (Últimas 24h)</h3>
    <canvas id="predictions-timeline" height="200"></canvas>
</div>

<script>
fetch('/api/ml/metrics/predictions/hourly?hours=24')
    .then(r => r.json())
    .then(data => {
        const ctx = document.getElementById('predictions-timeline').getContext('2d');

        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map(h => h.hour_timestamp),
                datasets: [
                    {
                        label: 'Malicious',
                        data: data.map(h => h.malicious_predictions),
                        borderColor: 'rgb(220, 38, 38)',
                        backgroundColor: 'rgba(220, 38, 38, 0.1)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Normal',
                        data: data.map(h => h.normal_predictions),
                        borderColor: 'rgb(34, 197, 94)',
                        backgroundColor: 'rgba(34, 197, 94, 0.1)',
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    });
</script>
```

**6. Distribución de Confianza**
```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">Distribución de Confianza (24h)</h3>
    <canvas id="confidence-distribution" height="250"></canvas>
</div>

<script>
fetch('/api/ml/metrics/predictions/summary')
    .then(r => r.json())
    .then(data => {
        const ctx = document.getElementById('confidence-distribution').getContext('2d');

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['>90% (Very High)', '80-90% (High)', '70-80% (Medium)', '<70% (Low)'],
                datasets: [{
                    data: [
                        data.predictions_over_90,
                        data.predictions_80_90,
                        data.predictions_70_80,
                        data.predictions_under_70
                    ],
                    backgroundColor: [
                        'rgba(220, 38, 38, 0.8)',   // Rojo
                        'rgba(251, 146, 60, 0.8)',  // Naranja
                        'rgba(234, 179, 8, 0.8)',   // Amarillo
                        'rgba(34, 197, 94, 0.8)'    // Verde
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    });
</script>
```

**7. Info del Modelo**
```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">Información del Modelo</h3>
    <div class="space-y-3">
        <div class="flex justify-between border-b pb-2">
            <span class="text-gray-600">Versión:</span>
            <span id="model-version" class="font-semibold">-</span>
        </div>
        <div class="flex justify-between border-b pb-2">
            <span class="text-gray-600">Último Entrenamiento:</span>
            <span id="last-trained" class="font-semibold">-</span>
        </div>
        <div class="flex justify-between border-b pb-2">
            <span class="text-gray-600">Training Samples:</span>
            <span id="training-samples" class="font-semibold">-</span>
        </div>
        <div class="flex justify-between border-b pb-2">
            <span class="text-gray-600">Test Samples:</span>
            <span id="test-samples" class="font-semibold">-</span>
        </div>
        <div class="flex justify-between border-b pb-2">
            <span class="text-gray-600">Total Features:</span>
            <span id="feature-count" class="font-semibold">-</span>
        </div>
        <div class="flex justify-between border-b pb-2">
            <span class="text-gray-600">Duración Entrenamiento:</span>
            <span id="training-duration" class="font-semibold">-</span>
        </div>
        <div class="mt-4">
            <button onclick="trainModel()" class="w-full px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700">
                <i class="fas fa-graduation-cap mr-2"></i>
                Re-entrenar Modelo
            </button>
        </div>
    </div>
</div>
```

### Tareas de Implementación - Semana 6

**Días 1-2: Base de Datos y Modificaciones**
- [ ] Crear modelos `MLModelMetrics` y `MLPredictionMetrics`
- [ ] Migración de base de datos
- [ ] Modificar `ml_detector.py` para guardar métricas
- [ ] Testing de logging de métricas

**Día 3: API**
- [ ] Crear `ml_metrics_routes.py`
- [ ] Implementar endpoints
- [ ] Testing de queries

**Días 4-5: Frontend y Deploy**
- [ ] Crear `ml_metrics.html`
- [ ] Implementar todos los gráficos (Chart.js)
- [ ] Agregar menú "ML Metrics" en sidebar
- [ ] Testing de UI
- [ ] Documentación
- [ ] Deploy a producción

### Entregables

1. ✅ Dashboard completo de métricas ML
2. ✅ 7 visualizaciones (accuracy, precision, recall, F1, confusion matrix, feature importance, predictions timeline)
3. ✅ Historial de entrenamientos (últimos 30 días)
4. ✅ Métricas de predicciones en tiempo real
5. ✅ Auto-refresh cada 60 segundos
6. ✅ Manual de usuario

### Métricas de Éxito

- ✅ Dashboard carga en < 2 segundos
- ✅ Métricas se actualizan automáticamente
- ✅ Admin puede identificar degradación del modelo
- ✅ Feature importance muestra las 18 features de Zeek
- ✅ Gráficos son interactivos y responsivos

---

## Fase 5: Sistema de Reportes (ALTA)

**Duración:** 1.5 semanas
**Prioridad:** 🟠 ALTA
**Semanas:** 7-8

### Objetivo

Crear sistema de reportes automáticos (PDF/HTML) con estadísticas de seguridad, enviables por email.

### Componentes a Desarrollar

#### 5.1. Modelo de Base de Datos

**Archivo:** `database/models.py`

```python
class ReportTemplate(Base):
    """Plantillas de reportes"""
    id, template_name, report_type (daily/weekly/monthly/custom)
    sections (JSON), # ['summary', 'ml_stats', 'zeek_detections', 'top_threats', ...]
    format (pdf/html/both)
    email_recipients (JSON)
    is_scheduled, schedule_cron
    created_at, updated_at

class GeneratedReport(Base):
    """Historial de reportes generados"""
    id, template_id, period_start, period_end
    format, file_path, file_size_kb
    email_sent, email_sent_at
    generated_at, generated_by
```

#### 5.2. Módulo de Reportes

**Archivo:** `modules/report_generator.py` (NUEVO - ~800 líneas)

**Dependencias:**
```bash
pip install reportlab jinja2 weasyprint
```

**Funcionalidades:**
```python
class ReportGenerator:
    def generate_report(self, template_id, period_start, period_end):
        """Generar reporte completo"""

    def _generate_html_report(self, data, template):
        """Generar HTML con Jinja2"""

    def _generate_pdf_report(self, html_content):
        """Convertir HTML a PDF con WeasyPrint"""

    def _collect_data(self, period_start, period_end):
        """Recolectar datos de DB para el reporte"""
        return {
            'summary': {...},
            'ml_stats': {...},
            'zeek_detections': {...},
            'top_threats': [...],
            'fail2ban_stats': {...},
            'alerts_sent': [...],
            'auto_blocks': [...]
        }

    def send_report_email(self, report_id, recipients):
        """Enviar reporte por email con archivo adjunto"""
```

#### 5.3. Plantillas HTML de Reportes

**Archivo:** `templates/reports/security_report.html` (NUEVO - ~600 líneas)

**Estructura del reporte:**

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        /* CSS para PDF */
        body { font-family: Arial, sans-serif; }
        .header { background: #1e40af; color: white; padding: 20px; }
        .section { page-break-inside: avoid; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        .chart { max-width: 600px; margin: 20px auto; }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <h1>Security Report</h1>
        <p>Period: {{ period_start }} - {{ period_end }}</p>
        <p>Generated: {{ generated_at }}</p>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="grid">
            <div class="card">
                <h3>Total Threats Detected</h3>
                <p class="number">{{ summary.total_threats }}</p>
            </div>
            <div class="card">
                <h3>IPs Blocked</h3>
                <p class="number">{{ summary.ips_blocked }}</p>
            </div>
            <div class="card">
                <h3>ML Accuracy</h3>
                <p class="number">{{ summary.ml_accuracy }}%</p>
            </div>
        </div>
    </div>

    <!-- ML Statistics -->
    <div class="section">
        <h2>Machine Learning Statistics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Total Predictions</td>
                <td>{{ ml_stats.total_predictions }}</td>
            </tr>
            <tr>
                <td>Malicious Detected</td>
                <td>{{ ml_stats.malicious_count }} ({{ ml_stats.malicious_percent }}%)</td>
            </tr>
            <tr>
                <td>Average Confidence</td>
                <td>{{ ml_stats.avg_confidence }}%</td>
            </tr>
        </table>
    </div>

    <!-- Zeek Detections -->
    <div class="section">
        <h2>Zeek Network Detections</h2>
        <table>
            <tr>
                <th>Detection Type</th>
                <th>Count</th>
            </tr>
            {% for detection in zeek_detections %}
            <tr>
                <td>{{ detection.type }}</td>
                <td>{{ detection.count }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <!-- Top Threats -->
    <div class="section">
        <h2>Top 20 Threat IPs</h2>
        <table>
            <tr>
                <th>#</th>
                <th>IP Address</th>
                <th>Country</th>
                <th>Threat Score</th>
                <th>ML Confidence</th>
                <th>Events</th>
            </tr>
            {% for threat in top_threats %}
            <tr>
                <td>{{ loop.index }}</td>
                <td>{{ threat.ip }}</td>
                <td>{{ threat.country }}</td>
                <td>{{ threat.score }}</td>
                <td>{{ threat.ml_confidence }}%</td>
                <td>{{ threat.event_count }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <!-- Charts (base64 embedded images) -->
    <div class="section">
        <h2>Threat Timeline</h2>
        <img src="data:image/png;base64,{{ charts.timeline }}" class="chart">
    </div>

    <div class="section">
        <h2>Geographic Distribution</h2>
        <img src="data:image/png;base64,{{ charts.geo_distribution }}" class="chart">
    </div>

    <!-- Footer -->
    <div class="footer">
        <p>Report generated by Security System</p>
        <p>Page <span class="page-number"></span></p>
    </div>
</body>
</html>
```

#### 5.4. API Endpoints

**Archivo:** `routes/report_routes.py` (NUEVO - ~250 líneas)

```python
GET    /api/reports/templates                # Listar plantillas
POST   /api/reports/templates                # Crear plantilla
PUT    /api/reports/templates/<id>           # Actualizar plantilla
DELETE /api/reports/templates/<id>           # Eliminar plantilla

POST   /api/reports/generate                 # Generar reporte ahora
GET    /api/reports/history                  # Historial de reportes generados
GET    /api/reports/download/<id>            # Descargar reporte
POST   /api/reports/send/<id>                # Enviar reporte por email

GET    /api/reports/preview                  # Vista previa de reporte (HTML)
```

#### 5.5. Interfaz Web

**Archivo:** `templates/reports_manager.html` (NUEVO - ~600 líneas)

**Secciones:**

**1. Generar Reporte Rápido**
```html
<div class="bg-white rounded-lg shadow p-6 mb-6">
    <h3 class="text-lg font-semibold mb-4">Generar Reporte Rápido</h3>

    <form id="quick-report-form">
        <div class="grid grid-cols-3 gap-4">
            <div>
                <label>Tipo de Reporte</label>
                <select name="report_type">
                    <option value="daily">Diario</option>
                    <option value="weekly">Semanal</option>
                    <option value="monthly">Mensual</option>
                    <option value="custom">Personalizado</option>
                </select>
            </div>

            <div>
                <label>Formato</label>
                <select name="format">
                    <option value="pdf">PDF</option>
                    <option value="html">HTML</option>
                    <option value="both">Ambos</option>
                </select>
            </div>

            <div>
                <label>Período</label>
                <input type="date" name="period_start">
                <input type="date" name="period_end">
            </div>
        </div>

        <div class="mt-4">
            <label>Enviar por Email a:</label>
            <input type="text" name="email_recipients" placeholder="admin@domain.com, security@domain.com">
        </div>

        <div class="mt-4 flex space-x-2">
            <button type="submit" class="px-6 py-2 bg-blue-600 text-white rounded">
                <i class="fas fa-file-pdf mr-2"></i>
                Generar Reporte
            </button>
            <button type="button" onclick="previewReport()" class="px-6 py-2 bg-gray-600 text-white rounded">
                <i class="fas fa-eye mr-2"></i>
                Vista Previa
            </button>
        </div>
    </form>
</div>
```

**2. Plantillas Programadas**
```html
<div class="bg-white rounded-lg shadow p-6 mb-6">
    <h3 class="text-lg font-semibold mb-4">Reportes Programados</h3>

    <table class="w-full">
        <thead>
            <tr>
                <th>Plantilla</th>
                <th>Tipo</th>
                <th>Formato</th>
                <th>Schedule</th>
                <th>Próxima Ejecución</th>
                <th>Estado</th>
                <th>Acciones</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>Security Daily Report</td>
                <td>Diario</td>
                <td>PDF</td>
                <td>Todos los días a las 8:00 AM</td>
                <td>2025-11-20 08:00</td>
                <td><span class="px-2 py-1 bg-green-500 text-white rounded text-xs">Activo</span></td>
                <td>
                    <button class="px-2 py-1 bg-blue-600 text-white rounded text-xs">Editar</button>
                    <button class="px-2 py-1 bg-red-600 text-white rounded text-xs">Eliminar</button>
                </td>
            </tr>
        </tbody>
    </table>

    <button onclick="createTemplate()" class="mt-4 px-4 py-2 bg-green-600 text-white rounded">
        <i class="fas fa-plus mr-2"></i>
        Nueva Plantilla Programada
    </button>
</div>
```

**3. Historial de Reportes Generados**
```html
<div class="bg-white rounded-lg shadow p-6">
    <h3 class="text-lg font-semibold mb-4">Historial de Reportes</h3>

    <table class="w-full">
        <thead>
            <tr>
                <th>Fecha</th>
                <th>Tipo</th>
                <th>Período</th>
                <th>Formato</th>
                <th>Tamaño</th>
                <th>Email Enviado</th>
                <th>Acciones</th>
            </tr>
        </thead>
        <tbody id="reports-history">
            <!-- Ejemplo -->
            <tr>
                <td>2025-11-19 08:05</td>
                <td>Diario</td>
                <td>2025-11-18 - 2025-11-19</td>
                <td>PDF</td>
                <td>245 KB</td>
                <td>✅ Sí</td>
                <td>
                    <a href="/api/reports/download/123" class="px-2 py-1 bg-blue-600 text-white rounded text-xs">
                        <i class="fas fa-download"></i> Descargar
                    </a>
                    <button onclick="resendReport(123)" class="px-2 py-1 bg-green-600 text-white rounded text-xs">
                        <i class="fas fa-envelope"></i> Reenviar
                    </button>
                </td>
            </tr>
        </tbody>
    </table>
</div>
```

### Integración con TaskScheduler

**Archivo:** `modules/task_scheduler.py` (modificar)

Agregar soporte para reportes programados:
```python
# Tarea 6: Reporte Diario (8:00 AM)
{
    'task_name': 'Daily Security Report',
    'task_type': 'report_generation',
    'module_name': 'modules.report_generator',
    'function_name': 'generate_scheduled_report',
    'function_params': {'template_id': 1},
    'schedule_type': 'daily',
    'daily_time': '08:00'
}
```

### Tareas de Implementación - Semana 7

**Días 1-2: Base de Datos y Módulo**
- [ ] Crear modelos `ReportTemplate` y `GeneratedReport`
- [ ] Migración de base de datos
- [ ] Implementar `report_generator.py`
- [ ] Testing de generación HTML

**Días 3-4: PDF y Email**
- [ ] Implementar generación de PDF (WeasyPrint)
- [ ] Implementar envío de email con adjuntos
- [ ] Crear plantilla HTML del reporte
- [ ] Testing de PDF

### Tareas de Implementación - Semana 8 (Día 1)

**Día 1: API y Frontend**
- [ ] Crear `report_routes.py`
- [ ] Crear `reports_manager.html`
- [ ] Testing de UI
- [ ] Documentación
- [ ] Deploy a producción

### Entregables

1. ✅ Sistema de reportes completo (PDF + HTML)
2. ✅ Reportes programados (diario/semanal/mensual)
3. ✅ Envío automático por email
4. ✅ Historial de reportes generados
5. ✅ Vista previa antes de generar
6. ✅ Plantilla profesional con gráficos
7. ✅ Manual de usuario

### Métricas de Éxito

- ✅ Reporte se genera en < 10 segundos
- ✅ PDF es profesional y legible
- ✅ Email se envía correctamente con adjunto
- ✅ Reportes programados ejecutan a tiempo
- ✅ Admin puede crear plantillas sin código

---

## Fase 6: Estadísticas de Fail2ban (ALTA)

**Duración:** 1 semana
**Prioridad:** 🟠 ALTA
**Semanas:** 8 (Días 2-5) y 9 (Días 1-2)

### Objetivo

Agregar visualizaciones y estadísticas avanzadas de Fail2ban.

### Componentes a Desarrollar

#### 6.1. Módulo de Estadísticas

**Archivo:** `modules/fail2ban_stats.py` (NUEVO - ~300 líneas)

```python
class Fail2banStats:
    def get_ban_timeline(self, hours=24, interval=60):
        """Timeline de bans por hora"""

    def get_bans_by_country(self, hours=24):
        """Distribución geográfica de bans"""

    def get_jail_effectiveness(self):
        """Efectividad de cada jail (bans, unbans, rate)"""

    def get_ban_duration_stats(self):
        """Estadísticas de duración de bans"""

    def get_repeat_offenders(self, limit=20):
        """IPs con más bans repetidos"""
```

#### 6.2. API Endpoints

**Archivo:** `app.py` (agregar endpoints)

```python
GET /api/fail2ban/stats/timeline?hours=24
GET /api/fail2ban/stats/by-country?hours=24
GET /api/fail2ban/stats/jail-effectiveness
GET /api/fail2ban/stats/repeat-offenders?limit=20
```

#### 6.3. Actualizar Interfaz Fail2ban

**Archivo:** `templates/fail2ban.html` (modificar - agregar ~300 líneas)

**Agregar secciones:**
- Timeline de bans (Chart.js)
- Mapa de países (Leaflet.js)
- Tabla de jail effectiveness
- Lista de repeat offenders

### Tareas de Implementación

**Días 1-2: Módulo y API**
- [ ] Crear `fail2ban_stats.py`
- [ ] Implementar funciones de estadísticas
- [ ] Agregar endpoints a `app.py`
- [ ] Testing

**Días 3-4: Frontend**
- [ ] Actualizar `fail2ban.html` con gráficos
- [ ] Implementar timeline (Chart.js)
- [ ] Implementar mapa de países
- [ ] Testing de UI

**Día 5: Deploy**
- [ ] Documentación
- [ ] Deploy a producción

### Entregables

1. ✅ 4 visualizaciones nuevas en Fail2ban
2. ✅ Timeline de bans
3. ✅ Mapa geográfico
4. ✅ Estadísticas de jails
5. ✅ Repeat offenders list

### Métricas de Éxito

- ✅ Estadísticas cargan en < 2 segundos
- ✅ Gráficos son interactivos
- ✅ Datos se actualizan automáticamente

---

## Fase 7: Integración Fail2ban + ML (ALTA)

**Duración:** 0.5 semanas
**Prioridad:** 🟠 ALTA
**Semanas:** 9 (Días 3-5)

### Objetivo

Permitir que ML sugiera reglas de Fail2ban automáticamente y sincronice bloqueos.

### Componentes a Desarrollar

#### 7.1. Módulo de Integración

**Archivo:** `modules/fail2ban_ml_integration.py` (NUEVO - ~250 líneas)

```python
class Fail2banMLIntegration:
    def suggest_jail_rules(self, hours_back=24):
        """
        Analizar detecciones ML y sugerir reglas de Fail2ban

        Returns:
            [{'pattern': '...',  'maxretry': 3, 'findtime': 600, 'reason': '...'}]
        """

    def sync_ml_blocks_to_fail2ban(self):
        """Sincronizar bloqueos ML → Fail2ban jail"""

    def auto_whitelist_low_confidence(self, threshold=0.3):
        """Whitelist IPs con ML confidence < 30%"""
```

#### 7.2. API Endpoints

```python
GET  /api/fail2ban/ml/suggestions          # Sugerencias de reglas
POST /api/fail2ban/ml/create-jail-from-ml  # Crear jail desde sugerencia ML
POST /api/fail2ban/ml/sync-blocks          # Sincronizar bloqueos ML → F2B
```

#### 7.3. Interfaz Web

**Archivo:** `templates/fail2ban_ml.html` (NUEVO - ~300 líneas)

- Lista de sugerencias de reglas
- Botón "Crear Jail" por sugerencia
- Configuración de sincronización automática

### Tareas de Implementación

**Días 1-2: Módulo y API**
- [ ] Crear `fail2ban_ml_integration.py`
- [ ] Implementar `suggest_jail_rules()`
- [ ] Implementar `sync_ml_blocks_to_fail2ban()`
- [ ] Agregar endpoints
- [ ] Testing

**Día 3: Frontend y Deploy**
- [ ] Crear `fail2ban_ml.html`
- [ ] Testing de integración
- [ ] Documentación
- [ ] Deploy a producción

### Entregables

1. ✅ Sugerencias automáticas de jails Fail2ban basadas en ML
2. ✅ Sincronización bidireccional ML ↔ Fail2ban
3. ✅ Interfaz para aprobar sugerencias
4. ✅ Auto-whitelist basado en ML confidence

### Métricas de Éxito

- ✅ Sugerencias son relevantes
- ✅ Sincronización funciona en ambas direcciones
- ✅ Admin puede aprobar/rechazar sugerencias

---

## Fase 8: Búsqueda Avanzada de Logs Zeek (MEDIA)

**Duración:** 1 semana
**Prioridad:** 🟡 MEDIA
**Semanas:** 10

### Objetivo

Agregar búsqueda avanzada y filtrado de logs de Zeek para investigaciones forenses.

### Componentes a Desarrollar

#### 8.1. API de Búsqueda

**Archivo:** `routes/zeek_routes.py` (modificar)

```python
POST /api/zeek/logs/search              # Búsqueda avanzada
POST /api/zeek/logs/export              # Exportar resultados (CSV/JSON)
GET  /api/zeek/logs/flow/<uid>          # Seguir flujo de conexión
```

**Parámetros de búsqueda:**
```json
{
  "log_type": "connections",
  "date_from": "2025-11-18",
  "date_to": "2025-11-19",
  "ip_address": "1.2.3.4",
  "port": 22,
  "protocol": "tcp",
  "country": "CN",
  "min_bytes": 1000000,
  "limit": 100
}
```

#### 8.2. Interfaz de Búsqueda

**Archivo:** `templates/zeek_search.html` (NUEVO - ~400 líneas)

- Formulario de búsqueda con múltiples filtros
- Tabla de resultados (DataTables.js)
- Botón "Exportar a CSV/JSON"
- Vista detallada de conexión individual

### Tareas de Implementación

**Días 1-3: Backend**
- [ ] Implementar búsqueda avanzada en `zeek_routes.py`
- [ ] Implementar exportación a CSV/JSON
- [ ] Implementar "follow the flow"
- [ ] Testing de queries complejas

**Días 4-5: Frontend y Deploy**
- [ ] Crear `zeek_search.html`
- [ ] Implementar formulario de búsqueda
- [ ] Implementar tabla de resultados
- [ ] Testing de UI
- [ ] Documentación
- [ ] Deploy a producción

### Entregables

1. ✅ Búsqueda avanzada con múltiples filtros
2. ✅ Exportación a CSV/JSON
3. ✅ Follow the flow (conexiones relacionadas)
4. ✅ Vista detallada por conexión

### Métricas de Éxito

- ✅ Búsqueda devuelve resultados en < 3 segundos
- ✅ Exportación funciona para > 10k registros
- ✅ Filtros combinables (AND/OR logic)

---

## Fase 9: Logs de Auditoría (MEDIA)

**Duración:** 1 semana
**Prioridad:** 🟡 MEDIA
**Semanas:** 11

### Objetivo

Registrar todas las acciones administrativas para auditoría y compliance.

### Componentes a Desarrollar

#### 9.1. Modelo de Base de Datos

**Archivo:** `database/models.py`

```python
class AuditLog(Base):
    """Registro de auditoría de acciones administrativas"""
    id, user_id, username
    action_type (block_ip/unblock_ip/create_jail/delete_rule/train_ml/...)
    resource_type (ip_address/jail/model/...)
    resource_id, details (JSON)
    ip_address (del admin), user_agent
    created_at
```

#### 9.2. Middleware de Auditoría

**Archivo:** `modules/audit_logger.py` (NUEVO - ~200 líneas)

```python
class AuditLogger:
    def log_action(self, user, action_type, resource_type, resource_id, details):
        """Registrar acción en audit log"""

    def get_audit_trail(self, user=None, action_type=None, hours=24):
        """Obtener historial de auditoría"""
```

#### 9.3. Integrar en Endpoints Críticos

Agregar logging a:
- Bloqueo/desbloqueo de IPs
- Creación/eliminación de jails
- Entrenamiento de modelo ML
- Cambios de configuración
- Creación de reglas de auto-bloqueo

#### 9.4. Interfaz Web

**Archivo:** `templates/audit_logs.html` (NUEVO - ~300 líneas)

- Tabla de audit logs
- Filtros (usuario, acción, fecha)
- Exportar a CSV

### Tareas de Implementación

**Días 1-2: Backend**
- [ ] Crear modelo `AuditLog`
- [ ] Migración de DB
- [ ] Crear `audit_logger.py`
- [ ] Integrar en endpoints críticos

**Días 3-4: Frontend**
- [ ] Crear `audit_logs.html`
- [ ] Implementar tabla y filtros
- [ ] Testing

**Día 5: Deploy**
- [ ] Documentación
- [ ] Deploy a producción

### Entregables

1. ✅ Audit trail completo de acciones administrativas
2. ✅ Dashboard de audit logs
3. ✅ Filtros por usuario/acción/fecha
4. ✅ Exportación a CSV

### Métricas de Éxito

- ✅ Todas las acciones críticas se registran
- ✅ Logs son inmutables (no editables)
- ✅ Admin puede rastrear cambios fácilmente

---

## Fase 10: Playbooks de Respuesta (MEDIA)

**Duración:** 1 semana
**Prioridad:** 🟡 MEDIA
**Semanas:** 12

### Objetivo

Crear workflows automatizados para respuesta a incidentes.

### Componentes a Desarrollar

#### 10.1. Modelo de Base de Datos

**Archivo:** `database/models.py`

```python
class Playbook(Base):
    """Playbooks de respuesta a incidentes"""
    id, playbook_name, trigger_type (ml_detection/zeek_detection/fail2ban_ban)
    trigger_conditions (JSON)
    actions (JSON), # [{'type': 'block_ip'}, {'type': 'send_alert'}, {'type': 'create_ticket'}]
    is_enabled, created_at, updated_at

class PlaybookExecution(Base):
    """Historial de ejecuciones de playbooks"""
    id, playbook_id, trigger_event (JSON)
    actions_executed (JSON), success, error_message
    executed_at
```

#### 10.2. Módulo de Playbooks

**Archivo:** `modules/playbook_engine.py` (NUEVO - ~400 líneas)

```python
class PlaybookEngine:
    def evaluate_triggers(self, event):
        """Evaluar si evento dispara algún playbook"""

    def execute_playbook(self, playbook_id, event):
        """Ejecutar acciones del playbook"""

    def _execute_action(self, action, context):
        """Ejecutar acción individual (block, alert, ticket, etc)"""
```

**Acciones soportadas:**
- `block_ip` - Bloquear IP
- `send_alert` - Enviar alerta (email/telegram)
- `create_ticket` - Crear ticket en sistema externo (Jira/GitHub)
- `run_script` - Ejecutar script personalizado
- `wait` - Esperar N segundos
- `conditional` - If/else logic

#### 10.3. Interfaz Web

**Archivo:** `templates/playbooks.html` (NUEVO - ~500 líneas)

- Editor visual de playbooks (drag & drop)
- Lista de playbooks activos
- Historial de ejecuciones

### Tareas de Implementación

**Días 1-3: Backend**
- [ ] Crear modelos
- [ ] Implementar `playbook_engine.py`
- [ ] Integrar con sistemas existentes
- [ ] Testing

**Días 4-5: Frontend y Deploy**
- [ ] Crear `playbooks.html`
- [ ] Editor visual de playbooks
- [ ] Testing
- [ ] Documentación
- [ ] Deploy a producción

### Entregables

1. ✅ Sistema de playbooks funcional
2. ✅ 5 playbooks pre-configurados
3. ✅ Editor visual de playbooks
4. ✅ Historial de ejecuciones
5. ✅ Integración con sistemas externos

### Métricas de Éxito

- ✅ Playbooks se ejecutan en < 5 segundos
- ✅ Admin puede crear playbooks sin código
- ✅ Playbooks reducen tiempo de respuesta en 80%

---

## Cronograma General

```
Semanas 1-2:   Fase 1  - Alertas y Notificaciones (CRÍTICA)
Semanas 3-4:   Fase 2  - Dashboard Integrado Zeek + ML (CRÍTICA)
Semana 5:      Fase 3  - Auto-Bloqueo Basado en ML (CRÍTICA)
Semana 6:      Fase 4  - Métricas del Modelo ML (CRÍTICA)
────────────────────────────────────────────────────────────
Semanas 7-8:   Fase 5  - Sistema de Reportes (ALTA)
Semanas 8-9:   Fase 6  - Estadísticas de Fail2ban (ALTA)
Semana 9:      Fase 7  - Integración Fail2ban + ML (ALTA)
────────────────────────────────────────────────────────────
Semana 10:     Fase 8  - Búsqueda Avanzada de Logs Zeek (MEDIA)
Semana 11:     Fase 9  - Logs de Auditoría (MEDIA)
Semana 12:     Fase 10 - Playbooks de Respuesta (MEDIA)
────────────────────────────────────────────────────────────
Total: 12 semanas (3 meses)
```

### Hitos (Milestones)

- **Semana 2:** Sistema de alertas funcional ✅
- **Semana 4:** Dashboard unificado completo ✅
- **Semana 6:** Automatización completa (alertas + auto-bloqueo + métricas) ✅
- **Semana 9:** Reporting y estadísticas avanzadas ✅
- **Semana 12:** Sistema completo con auditoría y playbooks ✅

---

## Recursos Necesarios

### Recursos Humanos

- **1 Desarrollador Full-Stack** (Backend + Frontend)
- **Tiempo dedicado:** 40 horas/semana (tiempo completo)
- **Opcional:** 1 QA Tester para testing en semanas 6, 9, 12

### Recursos Técnicos

#### Servidor de Desarrollo
- Ubuntu 24.04
- Mínimo 4GB RAM, 2 CPU cores
- Para testing antes de deploy a producción

#### Bibliotecas Python Nuevas
```bash
# Fase 1 - Alertas
pip install python-telegram-bot aiosmtplib

# Fase 2 - Dashboard
# (solo frontend, no requiere backend adicional)

# Fase 5 - Reportes
pip install reportlab jinja2 weasyprint

# Otras ya instaladas: flask, sqlalchemy, pandas, scikit-learn, etc.
```

#### Servicios Externos (Opcionales)

| Servicio | Propósito | Costo Estimado |
|----------|-----------|----------------|
| SMTP (Gmail/SendGrid) | Email alerts y reportes | Gratis (Gmail) / $15/mes (SendGrid) |
| Telegram Bot API | Alertas instantáneas | Gratis |
| Slack/Discord Webhooks | Alertas a equipos | Gratis |
| Jira API | Integración playbooks | $10/mes (plan básico) |

### Recursos de Infraestructura

- **Almacenamiento:** +5GB para reportes PDF (crecimiento mensual)
- **Backup diario de base de datos** (crítico para audit logs)
- **CDN para assets** (Chart.js, Leaflet.js) - usar CDNs públicos (gratis)

---

## Riesgos y Mitigación

### Riesgos Técnicos

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| **Rendimiento de queries DB con > 100k registros** | ALTA | ALTO | Agregar índices en columnas críticas (timestamp, ip_address). Implementar paginación. |
| **WeasyPrint falla en generar PDF** | MEDIA | MEDIO | Fallback a ReportLab. Testing en desarrollo primero. |
| **SMTP bloqueado por firewall** | MEDIA | ALTO | Usar múltiples proveedores (Gmail + SendGrid). Testing previo. |
| **False positives en auto-bloqueo ML** | ALTA | CRÍTICO | Implementar simulador. Empezar con threshold alto (90%). Whitelist manual. |
| **Chart.js no carga en navegadores viejos** | BAJA | BAJO | Polyfills. Mensaje de actualización de navegador. |

### Riesgos de Negocio

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| **Scope creep (nuevas funcionalidades)** | ALTA | MEDIO | Congelar scope después de Fase 6. Nuevas ideas → backlog para v2.0. |
| **Delay en testing** | MEDIA | MEDIO | Buffer de 1 semana al final (semana 13 opcional). |
| **Usuario no adopta nuevas funcionalidades** | BAJA | BAJO | Documentación clara. Videos tutoriales. Onboarding guiado. |

### Plan de Rollback

En caso de problemas críticos en producción:

1. **Git tags por fase** - Cada fase tiene tag (v1.1, v1.2, etc)
2. **Backup de DB antes de cada deploy**
3. **Feature flags** - Nuevas funcionalidades desactivables desde settings
4. **Rollback en < 15 minutos** - Script automatizado

```bash
# Rollback script
./scripts/rollback.sh v1.3  # Volver a versión anterior
```

---

## Métricas de Éxito del Proyecto

Al finalizar las 12 semanas, el sistema debe cumplir:

### Métricas Cuantitativas

| Métrica | Objetivo | Medición |
|---------|----------|----------|
| **Tiempo de respuesta a amenazas** | < 5 minutos | Desde detección hasta bloqueo |
| **Tasa de alertas enviadas** | > 95% éxito | Logs de AlertLog |
| **Accuracy del modelo ML** | > 95% | MLModelMetrics.accuracy |
| **Tiempo de generación de reportes** | < 10 segundos | Performance testing |
| **Uptime del sistema** | > 99.5% | Monitoring logs |
| **False positive rate** | < 5% | Manual review semanal |

### Métricas Cualitativas

- ✅ **Usabilidad:** Admin puede configurar alertas/políticas sin código
- ✅ **Visibilidad:** Dashboard muestra panorama completo en < 10 segundos
- ✅ **Auditoría:** Todas las acciones críticas tienen audit trail
- ✅ **Automatización:** 70% de bloqueos son automáticos
- ✅ **Documentación:** Manual de usuario completo por funcionalidad

---

## Notas Finales

### Orden Recomendado de Implementación

**NO cambiar el orden de las fases críticas (1-4).** Son dependencias entre sí:
1. Alertas primero (para notificar sobre todo lo demás)
2. Dashboard integrado (para visualizar lo que alertas detectan)
3. Auto-bloqueo (requiere alertas + dashboard para monitorear)
4. Métricas ML (para verificar que auto-bloqueo funciona bien)

**Las fases 5-10 pueden reordenarse** según prioridad de negocio.

### Testing

Cada fase debe incluir:
- **Unit tests** - Funciones críticas
- **Integration tests** - Endpoints API
- **UI tests** - Funcionalidad frontend
- **Performance tests** - Queries de DB

### Documentación

Cada fase debe entregar:
- **README técnico** - Arquitectura y código
- **Manual de usuario** - Screenshots y paso a paso
- **API docs** - Endpoints y ejemplos

### Mantenimiento Post-Implementación

Después de la semana 12:
- **Monitoring diario** - Revisar logs de errores
- **Backups automáticos** - DB + reportes generados
- **Updates semanales** - Paquetes de Python
- **Review mensual** - Métricas de éxito

---

## Aprobación e Inicio

**Preparado por:** Claude Code
**Fecha:** 2025-11-19
**Versión del documento:** 1.0

**Próximos pasos:**
1. Revisar y aprobar este plan
2. Preparar entorno de desarrollo
3. Iniciar Fase 1 (Alertas y Notificaciones)

**¿Listo para empezar? 🚀**
