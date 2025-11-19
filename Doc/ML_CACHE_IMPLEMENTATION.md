# Implementación del Sistema de Caché de Predicciones ML

## Problema Actual

Cada vez que entras a "Sugerencias ML", el sistema recalcula TODAS las predicciones desde cero, analizando las 66 IPs únicas con 345 eventos. Esto toma tiempo y recursos.

## Solución

Sistema de caché que:
1. Guarda las predicciones ML en base de datos
2. Solo analiza IPs nuevas o eventos nuevos
3. Muestra resultados instant

áneamente desde la caché

## Archivos Modificados

### ✅ 1. database/models.py - COMPLETADO

Ya se agregó la tabla `MLPrediction` con estos campos:
- `ip_address` - IP analizada
- `analyzed_at` - Cuándo se analizó
- `ml_confidence` - Confianza del modelo (0.0 - 1.0)
- `is_suspicious` - Si es sospechosa
- `total_events` - Total eventos de esta IP
- `country` - País detectado
- `reasons` - Razones del modelo
- `is_valid` - Si la predicción sigue siendo válida

### ⏳ 2. database/db_manager.py - PENDIENTE

Agregar al final del archivo (después de `remove_country_from_filter`):

```python
# ==================== PREDICCIONES ML (CACHÉ) ====================

def save_ml_prediction(self, ip_address, prediction_data, model_version='1.0'):
    """Guardar predicción ML para una IP en caché"""
    session = self.get_session()
    try:
        from database.models import MLPrediction

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
            existing.first_seen = prediction_data.get('first_seen')
            existing.last_seen = prediction_data.get('last_seen')
            existing.reasons = prediction_data.get('reasons', '')
            existing.recommended_action = prediction_data.get('recommended_action', 'monitor')
            existing.is_blocked = prediction_data.get('is_blocked', False)
            existing.model_version = model_version
            existing.is_valid = True
        else:
            # Crear nueva predicción
            prediction = MLPrediction(
                ip_address=ip_address,
                ml_confidence=prediction_data.get('ml_confidence', 0.0),
                is_suspicious=prediction_data.get('ml_confidence', 0.0) >= 0.6,
                is_anomaly=prediction_data.get('is_anomaly', False),
                total_events=prediction_data.get('total_events', 0),
                suspicious_events=prediction_data.get('suspicious_events', 0),
                anomaly_events=prediction_data.get('anomaly_events', 0),
                country=prediction_data.get('country', 'Unknown'),
                first_seen=prediction_data.get('first_seen'),
                last_seen=prediction_data.get('last_seen'),
                reasons=prediction_data.get('reasons', ''),
                recommended_action=prediction_data.get('recommended_action', 'monitor'),
                is_blocked=prediction_data.get('is_blocked', False),
                model_version=model_version,
                is_valid=True
            )
            session.add(prediction)

        session.commit()
        return True
    except Exception as e:
        session.rollback()
        print(f"Error saving ML prediction: {e}")
        return False
    finally:
        session.close()

def get_ml_predictions(self, hours_back=24, min_confidence=0.6, only_valid=True):
    """Obtener predicciones ML en caché"""
    session = self.get_session()
    try:
        from database.models import MLPrediction

        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)

        query = session.query(MLPrediction).filter(
            MLPrediction.ml_confidence >= min_confidence,
            MLPrediction.last_seen >= cutoff_time  # Filtrar por última actividad
        )

        if only_valid:
            query = query.filter(MLPrediction.is_valid == True)

        predictions = query.order_by(desc(MLPrediction.ml_confidence)).all()

        return [pred.to_dict() for pred in predictions]
    finally:
        session.close()

def invalidate_ml_predictions(self):
    """Invalidar todas las predicciones ML (cuando se re-entrena el modelo)"""
    session = self.get_session()
    try:
        from database.models import MLPrediction
        session.query(MLPrediction).update({'is_valid': False})
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        print(f"Error invalidating ML predictions: {e}")
        return False
    finally:
        session.close()
```

### ⏳ 3. modules/ml_detector.py - PENDIENTE

Modificar el método `get_suspicious_ips()` (línea 438) para usar caché:

```python
def get_suspicious_ips(self, hours_back=24, min_confidence=0.6, use_cache=True):
    """Obtener IPs sospechosas según el modelo ML con sistema de caché"""
    if self.model is None:
        return []

    print(f"\n🔍 Analizando eventos de las últimas {hours_back} horas...")
    print(f"   Umbral de confianza mínimo: {min_confidence*100:.0f}%")

    # PASO 1: Intentar usar caché si está habilitado
    if use_cache:
        print("   💾 Buscando predicciones en caché...")
        cached_predictions = self.db.get_ml_predictions(
            hours_back=hours_back,
            min_confidence=min_confidence
        )

        if cached_predictions:
            print(f"   ✅ Encontradas {len(cached_predictions)} predicciones en caché")

            # Verificar si hay IPs nuevas que analizar
            cached_ips = set(p['ip_address'] for p in cached_predictions)

            # Obtener IPs de eventos recientes
            events = self.db.get_security_events(limit=5000)
            recent_ips = set()

            # Filtrar por tiempo
            try:
                if hours_back > 24 * 365:
                    days_back = hours_back / 24
                    cutoff_time = datetime.utcnow() - timedelta(days=days_back)
                else:
                    cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
            except OverflowError:
                cutoff_time = datetime.utcnow() - timedelta(days=365)

            for event in events:
                timestamp = event.get('timestamp')
                if timestamp:
                    if isinstance(timestamp, str):
                        event_time = datetime.fromisoformat(timestamp)
                    else:
                        event_time = timestamp

                    if event_time >= cutoff_time:
                        ip = event.get('source_ip')
                        if ip:
                            recent_ips.add(ip)

            # IPs nuevas = IPs recientes que NO están en caché
            new_ips = recent_ips - cached_ips

            if new_ips:
                print(f"   🆕 Detectadas {len(new_ips)} IPs nuevas para analizar...")
                # Analizar solo las IPs nuevas
                new_predictions = self._analyze_specific_ips(list(new_ips), hours_back, min_confidence)

                # Combinar predicciones de caché + nuevas
                all_predictions = cached_predictions + new_predictions
                all_predictions.sort(key=lambda x: x['ml_confidence'], reverse=True)

                print(f"   ✅ Total: {len(all_predictions)} IPs sospechosas")
                return all_predictions
            else:
                print("   ✅ No hay IPs nuevas, usando caché completo")
                return cached_predictions

    # PASO 2: Si no hay caché o está deshabilitado, análisis completo
    print("   🔄 Realizando análisis completo (sin caché)...")
    return self._perform_full_analysis(hours_back, min_confidence)

def _analyze_specific_ips(self, ip_list, hours_back, min_confidence):
    """Analizar solo IPs específicas y guardar en caché"""
    print(f"   📊 Analizando {len(ip_list)} IPs específicas...")

    # Obtener eventos solo de estas IPs
    events = self.db.get_security_events(limit=5000)

    # Filtrar por tiempo y por IPs específicas
    try:
        if hours_back > 24 * 365:
            days_back = hours_back / 24
            cutoff_time = datetime.utcnow() - timedelta(days=days_back)
        else:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
    except OverflowError:
        cutoff_time = datetime.utcnow() - timedelta(days=365)

    filtered_events = []
    for event in events:
        ip = event.get('source_ip')
        if ip not in ip_list:
            continue

        timestamp = event.get('timestamp')
        if timestamp:
            if isinstance(timestamp, str):
                event_time = datetime.fromisoformat(timestamp)
            else:
                event_time = timestamp

            if event_time >= cutoff_time:
                filtered_events.append(event)

    # Agrupar por IP
    ip_events = {}
    for event in filtered_events:
        ip = event.get('source_ip')
        if ip not in ip_events:
            ip_events[ip] = []
        ip_events[ip].append(event)

    # Analizar cada IP
    suspicious_ips = []
    for ip, events_list in ip_events.items():
        # Predecir para cada evento
        predictions = []
        for event in events_list:
            pred = self.predict(event)
            predictions.append(pred)

        # Calcular métricas agregadas
        avg_confidence = np.mean([p['confidence'] for p in predictions])
        suspicious_count = sum(1 for p in predictions if p['is_suspicious'])
        anomaly_count = sum(1 for p in predictions if p['is_anomaly'])

        # Si la confianza promedio supera el umbral
        if avg_confidence >= min_confidence:
            # Obtener geo info usando el servicio de geolocalización
            country = 'Unknown'
            if self.geo_service:
                try:
                    geo_info = self.geo_service.get_country_info(ip)
                    if geo_info:
                        country = f"{geo_info['country_name']} ({geo_info['country_code']})"
                except:
                    pass

            prediction_data = {
                'ip_address': ip,
                'ml_confidence': float(avg_confidence),
                'total_events': len(events_list),
                'suspicious_events': suspicious_count,
                'anomaly_events': anomaly_count,
                'is_anomaly': anomaly_count > 0,
                'country': country,
                'first_seen': events_list[0].get('timestamp'),
                'last_seen': events_list[-1].get('timestamp'),
                'reasons': predictions[0]['reason'] if predictions else 'No reason',
                'is_blocked': self.db.is_ip_blocked(ip),
                'recommended_action': 'block' if avg_confidence > 0.8 else 'monitor'
            }

            suspicious_ips.append(prediction_data)

            # Guardar en caché
            self.db.save_ml_prediction(ip, prediction_data)

    print(f"   ✅ {len(suspicious_ips)} nuevas IPs sospechosas guardadas en caché")
    return suspicious_ips

def _perform_full_analysis(self, hours_back, min_confidence):
    """Análisis completo de todas las IPs (código original)"""
    # Este es el código original de get_suspicious_ips() que ya existe
    # (desde línea 446 hasta 537 del archivo actual)
    # No lo repito aquí para ahorrar espacio

    # Al final, GUARDAR TODAS LAS PREDICCIONES EN CACHÉ:
    for prediction in suspicious_ips:
        self.db.save_ml_prediction(prediction['ip_address'], prediction)

    return suspicious_ips
```

### ⏳ 4. modules/ml_detector.py - train_model() - PENDIENTE

Cuando se re-entrena el modelo, invalidar el caché (línea 350, al final del método `train_model`):

```python
def train_model(self):
    """Entrenar modelo de Machine Learning"""
    # ... código existente ...

    # Al final, DESPUÉS de guardar el modelo:
    self.save_model()

    # Invalidar caché de predicciones (modelo nuevo = predicciones viejas inválidas)
    print("\n🗑️  Invalidando caché de predicciones antiguas...")
    self.db.invalidate_ml_predictions()
    print("   ✅ Caché invalidado. Próximo análisis usará el nuevo modelo.")

    return True
```

## Flujo de Trabajo

### Primera Vez (Sin Caché)
1. Usuario entra a "Sugerencias ML"
2. Sistema analiza todas las IPs (66 IPs, 345 eventos)
3. **Guarda resultados en base de datos** (tabla `ml_predictions`)
4. Muestra resultados (39 IPs sospechosas)

### Segunda Vez en Adelante (Con Caché)
1. Usuario entra a "Sugerencias ML"
2. Sistema busca en caché → Encuentra 39 IPs ya analizadas
3. Verifica si hay IPs nuevas desde el último análisis
4. Si hay 5 IPs nuevas:
   - Analiza solo esas 5 IPs nuevas
   - Guarda en caché
   - Combina: 39 (caché) + 5 (nuevas) = 44 total
5. Muestra resultados **INSTANTÁNEAMENTE** (sin recalcular)

### Cuando se Re-Entrena el Modelo
1. Usuario entrena el modelo
2. Sistema marca todas las predicciones como `is_valid=False`
3. Próximo análisis re-calcula todo con el modelo nuevo
4. Guarda nuevas predicciones en caché

## Ventajas

- ⚡ **Velocidad**: Respuesta instantánea en lugar de 3-5 segundos
- 💾 **Eficiencia**: Solo analiza IPs nuevas
- 📊 **Historial**: Mantiene registro de predicciones pasadas
- 🔄 **Actualización**: Se invalida automáticamente al re-entrenar

## Instalación

1. La tabla `MLPrediction` se crea automáticamente al iniciar la app
2. Agregar métodos a `db_manager.py` (copiar código de arriba)
3. Modificar `ml_detector.py` según instrucciones
4. Reiniciar la aplicación Flask

## Testing

```python
# Probar guardar predicción
from database.db_manager import DatabaseManager

db = DatabaseManager()

# Guardar una predicción de prueba
test_prediction = {
    'ml_confidence': 0.95,
    'total_events': 10,
    'suspicious_events': 8,
    'anomaly_events': 2,
    'country': 'Unknown',
    'first_seen': datetime.utcnow(),
    'last_seen': datetime.utcnow(),
    'reasons': 'Test prediction',
    'recommended_action': 'block',
    'is_blocked': False
}

db.save_ml_prediction('192.168.1.100', test_prediction)

# Recuperar predicciones
predictions = db.get_ml_predictions(hours_back=24, min_confidence=0.6)
print(f"Found {len(predictions)} predictions")
```

## Mantenimiento

### Limpiar predicciones antiguas (opcional)

Agregar a `db_manager.py`:

```python
def cleanup_old_predictions(self, days_old=30):
    """Eliminar predicciones más antiguas de X días"""
    session = self.get_session()
    try:
        from database.models import MLPrediction
        cutoff = datetime.utcnow() - timedelta(days=days_old)

        deleted = session.query(MLPrediction).filter(
            MLPrediction.analyzed_at < cutoff
        ).delete()

        session.commit()
        print(f"🗑️  Eliminadas {deleted} predicciones antiguas")
        return deleted
    finally:
        session.close()
```

Ejecutar cada mes para mantener la base de datos limpia.

## Notas Importantes

- La primera carga después de implementar será lenta (crea el caché)
- Cargas subsiguientes serán instantáneas
- Al re-entrenar el modelo, el caché se invalida automáticamente
- El campo `is_valid` permite mantener historial pero marcar predicciones obsoletas
