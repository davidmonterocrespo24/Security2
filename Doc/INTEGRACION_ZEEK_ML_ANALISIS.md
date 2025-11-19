# Análisis: Integración de Zeek con Machine Learning

## 📊 Estado Actual

### ✅ Lo que funciona:
1. **Zeek está capturando tráfico** correctamente (1000 conexiones, 6 HTTP)
2. **Los datos se guardan en BD** en tablas separadas:
   - `zeek_connections` - Conexiones de red
   - `zeek_dns` - Consultas DNS
   - `zeek_http` - Tráfico HTTP
   - `zeek_ssl` - Conexiones SSL/TLS

3. **El modelo ML funciona** y analiza eventos de `security_events`

### ❌ Lo que falta:

**El modelo ML NO está usando los datos de Zeek para entrenar ni para detectar amenazas.**

Actualmente:
- El ML solo lee de la tabla `security_events`
- Los datos de Zeek están en tablas separadas (`zeek_connections`, `zeek_dns`, etc.)
- **No hay puente entre ambos sistemas**

---

## 🎯 Propuesta de Integración

### Opción 1: Enriquecer SecurityEvents con datos de Zeek (Recomendada)

Cuando se detecte un evento sospechoso:
1. Buscar datos de Zeek de esa IP
2. Agregar características de Zeek como features del ML:
   - Número de conexiones por minuto
   - Número de puertos escaneados
   - Ratio de paquetes enviados/recibidos
   - Consultas DNS sospechosas
   - Certificados SSL inválidos

**Ventajas:**
- ✅ Mejora la precisión del modelo
- ✅ No requiere reentrenar desde cero
- ✅ Usa datos reales de red

### Opción 2: Crear eventos automáticos desde Zeek

Cuando Zeek detecte:
- Port scans
- DNS tunneling
- Beaconing
- Certificados SSL sospechosos

→ Crear eventos en `security_events` automáticamente

**Ventajas:**
- ✅ El ML puede entrenar con estos eventos
- ✅ Detección proactiva
- ✅ Feed automático de datos

### Opción 3: Modelo ML específico para Zeek

Crear un modelo separado que:
- Entrena solo con datos de Zeek
- Detecta patrones de red anómalos
- Complementa al modelo principal

**Ventajas:**
- ✅ Especializado en tráfico de red
- ✅ No interfiere con el modelo actual

---

## 🚀 Implementación Recomendada (Opción 1 + Opción 2)

### Paso 1: Agregar características de Zeek al ML

Modificar `extract_features()` en `ml_detector.py`:

```python
def extract_features(self, events_data):
    # ... código actual ...

    # NUEVO: Agregar características de Zeek
    for event in events_data:
        ip = event.get('source_ip')

        # Obtener datos de Zeek para esta IP
        zeek_data = self._get_zeek_features(ip)

        features['zeek_connections_count'] = zeek_data['connections_count']
        features['zeek_ports_scanned'] = zeek_data['unique_ports']
        features['zeek_dns_queries'] = zeek_data['dns_queries']
        features['zeek_has_ssl_issues'] = zeek_data['has_ssl_issues']
        features['zeek_bytes_sent'] = zeek_data['bytes_sent']
        features['zeek_bytes_received'] = zeek_data['bytes_received']
```

### Paso 2: Crear eventos automáticos desde detecciones de Zeek

Cuando se importan logs de Zeek, detectar automáticamente:

```python
def import_zeek_logs_to_db():
    # ... importar logs ...

    # Después de importar, buscar amenazas
    port_scans = detect_port_scans()

    for scan in port_scans:
        # Crear evento en security_events
        create_security_event(
            event_type='port_scan',
            severity='high',
            source_ip=scan['ip'],
            details=f"Port scan detectado: {scan['ports_scanned']} puertos",
            detected_by='zeek'
        )
```

### Paso 3: Re-entrenar el modelo con datos de Zeek

Una vez que haya eventos generados desde Zeek:
```bash
python3 -c "from modules.ml_detector import MLTrafficDetector; from database.db_manager import DatabaseManager; db = DatabaseManager(); ml = MLTrafficDetector(db); ml.train_model()"
```

---

## 📈 Beneficios Esperados

### Antes (Sin Zeek):
- ML solo ve eventos de Fail2ban, SSH, Nginx
- No tiene contexto de red completo
- Puede perder amenazas sofisticadas

### Después (Con Zeek):
- ✅ **+18 características nuevas** de red
- ✅ Detecta port scans automáticamente
- ✅ Identifica DNS tunneling
- ✅ Detecta beaconing (C&C)
- ✅ Valida certificados SSL
- ✅ Analiza patrones de tráfico

### Ejemplos de detección mejorada:

**Caso 1: Botnet C&C**
- Antes: No detectado (solo hace peticiones HTTP normales)
- Después: Detectado por beaconing (conexiones regulares cada X minutos)

**Caso 2: Port Scanner**
- Antes: Solo detectado si Fail2ban lo baneó
- Después: Detectado en tiempo real por Zeek (15+ puertos)

**Caso 3: Exfiltración de datos**
- Antes: No detectado
- Después: Detectado por DNS tunneling o alto volumen de bytes enviados

---

## 🔧 ¿Quieres que implemente esto?

Te puedo implementar:

1. **Integración básica** (1-2 horas):
   - Agregar features de Zeek al ML
   - Crear eventos automáticos desde port scans de Zeek
   - Re-entrenar el modelo

2. **Integración completa** (3-4 horas):
   - Todo lo anterior +
   - Detección de DNS tunneling → eventos
   - Detección de beaconing → eventos
   - SSL analysis → eventos
   - Dashboard mejorado con métricas de Zeek+ML

3. **Solo probar el modelo actual con datos existentes**:
   - Re-entrenar el modelo con los 1000 eventos de Zeek existentes
   - Ver qué IPs sospechosas detecta

**¿Qué opción prefieres?**
