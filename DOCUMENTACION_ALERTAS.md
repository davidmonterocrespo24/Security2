# Sistema de Alertas y Notificaciones

**Version:** 1.0
**Fecha:** 2025-11-19
**Estado:** Implementado (90% completo)

---

## Indice

1. [Introduccion](#introduccion)
2. [Arquitectura](#arquitectura)
3. [Instalacion y Configuracion](#instalacion-y-configuracion)
4. [Uso](#uso)
5. [API REST](#api-rest)
6. [Integraciones](#integraciones)
7. [Troubleshooting](#troubleshooting)

---

## Introduccion

El Sistema de Alertas y Notificaciones proporciona capacidades de alerta en tiempo real para el sistema de seguridad VPS. Permite enviar notificaciones automaticas via email (con soporte futuro para Telegram, Slack, Discord, Webhook) cuando se detectan eventos de seguridad.

### Caracteristicas Principales

- **Alertas por Email (SMTP)** - Soporte para Gmail, Outlook, SendGrid
- **Reglas Configurables** - Sistema flexible de reglas basadas en condiciones
- **Multiples Canales** - Soporte para multiples destinatarios y canales
- **Cooldown Inteligente** - Evita spam de alertas duplicadas
- **Integracion Completa** - Integrado con ML, Zeek y Fail2ban
- **Dashboard Web** - Interfaz completa para gestion
- **Estadisticas** - Metricas de alertas enviadas, exito/fallo, por severidad

---

## Arquitectura

### Componentes

```
Sistema de Alertas
├── Base de Datos
│   ├── AlertChannel     (Canales de notificacion)
│   ├── AlertRule        (Reglas de alerta)
│   └── AlertLog         (Historial de alertas)
│
├── Backend
│   ├── alert_manager.py (Motor de alertas)
│   └── alert_routes.py  (API REST)
│
├── Frontend
│   └── alerts_config.html (Dashboard web)
│
└── Integraciones
    ├── ml_detector.py
    ├── zeek_ml_integration.py
    └── fail2ban_manager.py
```

### Modelos de Base de Datos

#### AlertChannel
Representa un canal de notificacion (email, telegram, etc.)

**Campos:**
- `id` - ID unico
- `channel_name` - Nombre del canal
- `channel_type` - Tipo (email, telegram, slack, discord, webhook)
- `config` - JSON con configuracion (destinatarios, tokens, etc.)
- `is_enabled` - Si esta habilitado
- `is_verified` - Si se ha verificado con una prueba
- `total_alerts_sent` - Total de alertas enviadas
- `successful_sends` - Envios exitosos
- `failed_sends` - Envios fallidos

#### AlertRule
Define reglas para disparar alertas automaticamente

**Campos:**
- `id` - ID unico
- `rule_name` - Nombre de la regla
- `rule_type` - Tipo (ml_prediction, zeek_detection, fail2ban_ban)
- `conditions` - JSON con condiciones de evaluacion
- `severity_threshold` - Severidad minima (LOW, MEDIUM, HIGH, CRITICAL)
- `channel_ids` - JSON con IDs de canales a usar
- `cooldown_minutes` - Minutos entre alertas del mismo tipo
- `message_template` - Plantilla Jinja2 para el mensaje
- `is_enabled` - Si esta activa
- `times_triggered` - Veces que se ha disparado

#### AlertLog
Historial de todas las alertas enviadas

**Campos:**
- `id` - ID unico
- `rule_id` - FK a AlertRule
- `channel_id` - FK a AlertChannel
- `severity` - Severidad del evento
- `subject` - Asunto del mensaje
- `message` - Cuerpo del mensaje
- `event_metadata` - JSON con datos del evento
- `sent_at` - Timestamp de envio
- `success` - Si se envio exitosamente
- `error_message` - Mensaje de error si fallo

---

## Instalacion y Configuracion

### Paso 1: Ejecutar Migracion

```bash
python migrate_db.py
```

Esto crea:
- Tablas de base de datos
- 1 canal de email por defecto (deshabilitado)
- 5 reglas de alerta predefinidas (inactivas)

### Paso 2: Configurar SMTP en .env

Editar archivo `.env`:

```bash
# Configuracion SMTP para alertas por email
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu-email@gmail.com
SMTP_PASSWORD=tu-password-de-aplicacion
SMTP_FROM=Security System <tu-email@gmail.com>
ALERT_EMAIL_TO=admin@tudominio.com,security@tudominio.com
```

**IMPORTANTE para Gmail:**
1. Habilitar autenticacion de 2 factores
2. Generar "Contrasena de aplicacion" en https://myaccount.google.com/apppasswords
3. Usar esa contrasena en `SMTP_PASSWORD`

**Para Outlook:**
```bash
SMTP_SERVER=smtp-mail.outlook.com
SMTP_PORT=587
```

**Para SendGrid:**
```bash
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=tu-api-key-de-sendgrid
```

### Paso 3: Configurar Canales en Dashboard

1. Iniciar aplicacion: `python app.py`
2. Acceder a http://localhost:5000/alerts/
3. Click en "Nuevo Canal"
4. Completar:
   - Nombre: "Email Administradores"
   - Tipo: Email (SMTP)
   - Destinatarios: admin@example.com, security@example.com
   - Habilitar: SI
5. Click "Guardar"
6. Click boton "Test" para probar envio

### Paso 4: Activar Reglas

En la pestana "Reglas":
1. Click en icono "Play" de cada regla que desees activar
2. Puedes editar las reglas para personalizar:
   - Severidad minima
   - Canales de notificacion
   - Cooldown

---

## Uso

### Dashboard Web

Acceder a `/alerts/` para:

**Pestaña Canales:**
- Ver canales configurados
- Agregar/editar/eliminar canales
- Probar envio de alertas
- Habilitar/deshabilitar canales

**Pestaña Reglas:**
- Ver reglas activas/inactivas
- Crear nuevas reglas personalizadas
- Editar condiciones y configuracion
- Ver estadisticas de disparos

**Pestaña Historial:**
- Ver ultimas alertas enviadas (24h)
- Filtrar por severidad
- Ver tasa de exito/fallo
- Detalles completos de cada alerta

**Seccion de Prueba:**
- Enviar alerta de prueba manual
- Seleccionar severidad
- Mensaje personalizado

### Tipos de Eventos Soportados

#### ML Prediction
Disparado cuando el modelo ML detecta trafico sospechoso

**Campos del evento:**
- `type`: 'ml_prediction'
- `severity`: 'HIGH' o 'MEDIUM'
- `ip`: IP origen
- `confidence`: 0-100
- `ml_confidence`: 0.0-1.0
- `country`: Pais de origen
- `reason`: Razon de la prediccion

**Ejemplo de regla:**
```json
{
  "rule_name": "ML Alta Confianza",
  "rule_type": "ml_prediction",
  "conditions": {
    "confidence": {"operator": ">", "value": 80}
  },
  "severity_threshold": "MEDIUM"
}
```

#### Zeek Detection
Disparado por detecciones de Zeek Network Monitor

**Tipos de deteccion:**
- Port Scan
- DNS Tunneling
- DGA Domains
- Beaconing (C&C)
- SSL Self-Signed

**Campos del evento:**
- `type`: 'zeek_detection'
- `detection_type`: 'port_scan', 'dns_tunneling', etc.
- `severity`: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
- `ip`: IP origen
- Campos especificos segun tipo de deteccion

**Ejemplo de regla:**
```json
{
  "rule_name": "Zeek Beaconing C&C",
  "rule_type": "zeek_detection",
  "conditions": {
    "detection_type": {"operator": "==", "value": "beaconing"}
  },
  "severity_threshold": "CRITICAL"
}
```

#### Fail2ban Ban
Disparado cuando Fail2ban bloquea una IP

**Campos del evento:**
- `type`: 'fail2ban_ban'
- `severity`: 'HIGH' o 'MEDIUM'
- `ip`: IP bloqueada
- `jail`: Nombre de la jail

**Ejemplo de regla:**
```json
{
  "rule_name": "Fail2ban SSH",
  "rule_type": "fail2ban_ban",
  "conditions": {
    "jail": {"operator": "==", "value": "sshd"}
  },
  "severity_threshold": "HIGH"
}
```

### Operadores de Condiciones

Las reglas soportan los siguientes operadores:

- `>` - Mayor que (numerico)
- `<` - Menor que (numerico)
- `>=` - Mayor o igual (numerico)
- `<=` - Menor o igual (numerico)
- `==` - Igual (string o numerico)
- `!=` - Diferente (string o numerico)
- `in` - Contenido en lista
- `not_in` - No contenido en lista
- `contains` - Contiene substring

**Ejemplo complejo:**
```json
{
  "conditions": {
    "confidence": {"operator": ">", "value": 80},
    "country": {"operator": "in", "value": ["CN", "RU", "KP"]},
    "severity": {"operator": "==", "value": "HIGH"}
  }
}
```

### Cooldown

El cooldown previene spam de alertas repetidas:

- `0 minutos` - Sin limite (alerta cada vez)
- `5 minutos` - Alerta max 1 vez cada 5 min
- `60 minutos` - Alerta max 1 vez por hora
- `1440 minutos` - Alerta max 1 vez al dia

**Recomendaciones:**
- ML Predictions: 15-30 minutos
- Port Scans: 10-20 minutos
- DNS Tunneling: 30 minutos
- Beaconing: 0 minutos (siempre alertar)
- Fail2ban: 5-10 minutos

---

## API REST

Base URL: `/alerts/api/`

### Canales

#### GET /channels
Listar todos los canales

**Response:**
```json
{
  "success": true,
  "channels": [
    {
      "id": 1,
      "channel_name": "Email Principal",
      "channel_type": "email",
      "is_enabled": true,
      "is_verified": true,
      "total_alerts_sent": 45,
      "successful_sends": 43,
      "failed_sends": 2
    }
  ],
  "total": 1
}
```

#### POST /channels
Crear nuevo canal

**Request:**
```json
{
  "channel_name": "Email Ops",
  "channel_type": "email",
  "config": {
    "recipients": ["ops@example.com"]
  },
  "description": "Canal para equipo de operaciones",
  "is_enabled": true
}
```

#### PUT /channels/<id>
Actualizar canal

#### DELETE /channels/<id>
Eliminar canal

#### POST /channels/<id>/test
Enviar email de prueba

#### POST /channels/<id>/toggle
Habilitar/deshabilitar canal

### Reglas

#### GET /rules
Listar reglas

**Query params:**
- `rule_type` - Filtrar por tipo
- `is_enabled` - Filtrar por estado

#### POST /rules
Crear nueva regla

**Request:**
```json
{
  "rule_name": "ML Critico",
  "rule_type": "ml_prediction",
  "conditions": {
    "confidence": {"operator": ">", "value": 90}
  },
  "severity_threshold": "HIGH",
  "channel_ids": [1, 2],
  "cooldown_minutes": 30,
  "is_enabled": true
}
```

#### PUT /rules/<id>
Actualizar regla

#### DELETE /rules/<id>
Eliminar regla

#### POST /rules/<id>/toggle
Habilitar/deshabilitar regla

### Logs

#### GET /logs
Historial de alertas

**Query params:**
- `limit` - Max registros (default: 100)
- `severity` - Filtrar por severidad
- `success` - Solo exitosas (true/false)
- `hours_back` - Horas hacia atras (default: 24)

#### GET /logs/stats
Estadisticas de alertas

**Response:**
```json
{
  "success": true,
  "stats": {
    "total_sent": 120,
    "successful": 115,
    "failed": 5,
    "success_rate": 95.83,
    "by_severity": {
      "low": 30,
      "medium": 50,
      "high": 35,
      "critical": 5
    },
    "active_channels": 2,
    "active_rules": 5
  }
}
```

### Pruebas

#### POST /test-alert
Enviar alerta de prueba

**Request:**
```json
{
  "message": "Prueba del sistema",
  "severity": "MEDIUM"
}
```

---

## Integraciones

### Machine Learning (ml_detector.py)

**Cuando se dispara:**
- Prediccion = maliciosa (1)
- Confianza >= 80%

**Configuracion:**
El AlertManager se inicializa automaticamente en `MLTrafficDetector.__init__()`.

**Codigo:**
```python
if self.alert_manager and prediction == 1 and confidence >= 0.8:
    self.alert_manager.process_alert({
        'type': 'ml_prediction',
        'severity': 'HIGH' if confidence >= 0.9 else 'MEDIUM',
        'ip': event_data['source_ip'],
        'confidence': int(confidence * 100),
        # ... mas campos
    })
```

### Zeek Network Monitor (zeek_ml_integration.py)

**Detecciones soportadas:**
1. Port Scan - Escaneo de puertos
2. DNS Tunneling - Exfiltracion via DNS
3. DGA Domains - Dominios generados algoritmicamente
4. Beaconing - Comunicacion C&C
5. SSL Self-Signed - Certificados autofirmados

**Configuracion:**
El AlertManager se inicializa automaticamente en `ZeekMLIntegration.__init__()`.

**Ejemplo:**
```python
if self.alert_manager:
    self.alert_manager.process_alert({
        'type': 'zeek_detection',
        'detection_type': 'beaconing',
        'severity': 'CRITICAL',
        'ip': beacon['source_ip'],
        'dest_ip': beacon['dest_ip'],
        # ... mas campos
    })
```

### Fail2ban (fail2ban_manager.py)

**Cuando se dispara:**
1. Ban manual de IP via API
2. Monitoreo periodico de logs (`monitor_and_alert_bans()`)

**Configuracion:**
```python
# En app.py
fail2ban_manager = Fail2banManager(db_manager)
```

**Uso desde Task Scheduler:**
```python
from modules.fail2ban_manager import fail2ban_monitor_and_alert

# Programar tarea cada 10 minutos
task = {
    'name': 'Fail2ban Monitor',
    'function_name': 'fail2ban_monitor_and_alert',
    'schedule_type': 'interval',
    'interval_minutes': 10
}
```

---

## Troubleshooting

### No se envian alertas

**Problema:** Las reglas estan activas pero no se envian alertas.

**Soluciones:**
1. Verificar que el canal este habilitado
2. Verificar credenciales SMTP en `.env`
3. Verificar que la regla coincida con el evento:
   - Revisar `rule_type` vs `event.type`
   - Revisar `severity_threshold`
   - Revisar condiciones
4. Verificar cooldown de la regla
5. Ver logs en `/alerts/api/logs`

### Error de autenticacion SMTP

**Problema:** `SMTP authentication failed`

**Soluciones:**
1. Gmail: Usar "Contrasena de aplicacion", no la contrasena normal
2. Verificar que el usuario/password sean correctos
3. Verificar firewall/puerto 587
4. Probar con `telnet smtp.gmail.com 587`

### Emails no llegan

**Problema:** Envio exitoso pero email no llega.

**Soluciones:**
1. Revisar carpeta SPAM
2. Verificar email destino correcto
3. Verificar dominio `SMTP_FROM` coincida con `SMTP_USER`
4. Configurar SPF/DKIM si usas dominio propio
5. Probar envio de prueba desde canal

### Reglas no coinciden

**Problema:** Eventos generados pero reglas no se disparan.

**Soluciones:**
1. Verificar `rule_type` en regla = `type` en evento
2. Verificar operadores en condiciones:
   ```python
   # Correcto
   {"confidence": {"operator": ">", "value": 80}}

   # Incorrecto
   {"confidence": 80}  # Falta operador
   ```
3. Verificar tipos de datos (numerico vs string)
4. Habilitar logging en `alert_manager.py`:
   ```python
   print(f"Evaluando regla {rule.rule_name}: {self.evaluate_rule(rule, event)}")
   ```

### Demasiadas alertas (spam)

**Problema:** Se envian muchas alertas repetidas.

**Soluciones:**
1. Aumentar `cooldown_minutes` en reglas
2. Subir `severity_threshold` (ej: LOW -> MEDIUM)
3. Ajustar condiciones para ser mas estrictas
4. Usar operador `>` en vez de `>=` para confianza

### Error en integracion ML/Zeek

**Problema:** Eventos se generan pero no llegan al alert_manager.

**Soluciones:**
1. Verificar que `alert_manager` se inicializa:
   ```python
   # En ml_detector.py
   if self.alert_manager:
       print("AlertManager OK")
   else:
       print("AlertManager NO inicializado")
   ```
2. Verificar que se pasa `db_manager` al constructor
3. Ver excepciones en console con:
   ```python
   try:
       self.alert_manager.process_alert(event)
   except Exception as e:
       import traceback
       traceback.print_exc()
   ```

---

## Testing

### Script de Pruebas

Ejecutar suite completa de tests:

```bash
python test_alerts.py
```

**Tests incluidos:**
1. Verificacion de modelos de BD
2. AlertManager inicializacion
3. Procesamiento de alertas
4. Integracion con Zeek
5. Integracion con ML
6. Integracion con Fail2ban

### Prueba Manual de Email

1. Ir a `/alerts/`
2. Click pestana "Canales"
3. Click boton "Test" en canal de email
4. Verificar recepcion de email

### Prueba de Alerta Completa

1. Ir a `/alerts/`
2. Seccion "Probar Sistema de Alertas"
3. Escribir mensaje de prueba
4. Seleccionar severidad
5. Click "Enviar Prueba"
6. Verificar en pestana "Historial"

---

## Estadisticas de Implementacion

- **Archivos creados:** 4 (migrate_db.py, alert_manager.py, alert_routes.py, alerts_config.html)
- **Archivos modificados:** 7 (models.py, .env.example, ml_detector.py, zeek_ml_integration.py, fail2ban_manager.py, base.html, app.py)
- **Lineas de codigo:** ~2000+
- **Tests pasados:** 5/6 (83%)
- **Progreso:** 90% completado

### Tareas Pendientes

1. ~~Testing de envio de emails~~ - Requiere credenciales SMTP reales
2. ~~Testing de UI~~ - Requiere servidor corriendo
3. Soporte para Telegram/Slack/Discord (futuro)
4. Plantillas HTML personalizables (futuro)
5. Dashboard de metricas avanzadas (futuro)

---

## Soporte

Para reportar bugs o solicitar features:
- Revisar logs en `/alerts/api/logs`
- Verificar configuracion en `.env`
- Ejecutar `python test_alerts.py`
- Revisar este documento

---

**Ultima actualizacion:** 2025-11-19
**Version:** 1.0.0
**Autor:** Security System Development Team
