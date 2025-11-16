# Sistema de Machine Learning para Detección de Tráfico Malicioso

## Resumen Ejecutivo

Se ha implementado un sistema completo de **Machine Learning** que aprende de los datos históricos del sistema de seguridad para **detectar y sugerir IPs sospechosas**. El modelo NO toma acciones automáticas, solo proporciona sugerencias que el administrador puede revisar y decidir si bloquear o no.

---

## 🧠 Características del Sistema ML

### 1. **Modelo No Invasivo**
- ✅ **Solo sugiere**, no bloquea automáticamente
- ✅ El administrador tiene control total
- ✅ Proporciona explicaciones de por qué es sospechoso
- ✅ Incluye nivel de confianza (0-100%)

### 2. **Dos Algoritmos Complementarios**

#### A. Random Forest Classifier
- **Propósito**: Clasificar tráfico como malicioso o normal
- **Tipo**: Supervised Learning
- **Salida**: Probabilidad de que sea malicioso (0-100%)
- **Ventajas**:
  - Alta precisión
  - Resistente a overfitting
  - Proporciona feature importance
  - Maneja datos desbalanceados

#### B. Isolation Forest
- **Propósito**: Detectar anomalías y comportamientos inusuales
- **Tipo**: Unsupervised Learning
- **Salida**: Score de anomalía
- **Ventajas**:
  - Detecta ataques nuevos (0-day)
  - No requiere etiquetas
  - Identifica patrones raros

### 3. **Extracción de Características**

El modelo analiza **20+ características** de cada evento:

#### Temporales:
- Hora del día (0-23)
- Día de la semana (0-6)
- ¿Es fin de semana? (0/1)
- ¿Es horario nocturno? (0/1)

#### De Severidad:
- Nivel de severidad (1=low, 2=medium, 3=high, 4=critical)

#### De Ataque:
- Vector de ataque (SQL injection, XSS, etc.)
- Tipo de evento

#### HTTP:
- Método (GET, POST, etc.)
- Longitud de la URL
- ¿Tiene query string?
- Caracteres sospechosos (<, >, ', ", ;, |, &)

#### User Agent:
- Longitud del user agent
- ¿Es un bot?

#### Geográficas:
- País de origen

---

## 📊 Cómo Funciona

### Fase 1: Entrenamiento

```
Datos Históricos → Extracción de Features → Entrenamiento → Modelo Guardado
    (eventos)         (20+ features)        (RF + IF)      (archivos .pkl)
```

1. **Recopila datos** de los últimos N días (configurable)
2. **Extrae características** de cada evento
3. **Etiqueta datos**:
   - Malicioso (1) = IP bloqueada O severidad crítica/alta
   - Normal (0) = resto
4. **Divide datos** en entrenamiento (80%) y prueba (20%)
5. **Entrena Random Forest** (100 árboles)
6. **Entrena Isolation Forest** (detección de anomalías)
7. **Evalúa rendimiento** (accuracy, precision, recall)
8. **Guarda modelo** en disco

### Fase 2: Predicción

```
Nuevo Evento → Extracción Features → Predicción ML → Sugerencia
                  (mismo proceso)      (RF + IF)    (con confianza)
```

1. **Recibe evento** nuevo
2. **Extrae características** (igual que entrenamiento)
3. **Predice con RF**: ¿Es malicioso? → Confianza %
4. **Predice con IF**: ¿Es anomalía? → Score
5. **Genera explicación** de por qué es sospechoso
6. **Retorna sugerencia** con nivel de confianza

### Fase 3: Análisis Agregado

```
Eventos por IP → Predicciones ML → Agregación → Sugerencias Finales
   (últimas 24h)      (cada evento)    (promedio)   (ordenadas por confianza)
```

1. **Agrupa eventos** por IP
2. **Predice** para cada evento de la IP
3. **Calcula promedio** de confianza
4. **Cuenta** eventos sospechosos y anomalías
5. **Determina recomendación**:
   - Confianza > 80% → **BLOQUEAR**
   - Confianza 60-80% → **MONITOREAR**
6. **Ordena por confianza** descendente

---

## 🎯 Métricas de Evaluación

### Accuracy (Exactitud)
- **Definición**: % de predicciones correctas
- **Fórmula**: (TP + TN) / Total
- **Objetivo**: > 85%

### Precision (Precisión)
- **Definición**: % de predicciones maliciosas que son correctas
- **Fórmula**: TP / (TP + FP)
- **Objetivo**: > 80%
- **Importancia**: Minimizar falsos positivos

### Recall (Sensibilidad)
- **Definición**: % de maliciosos detectados
- **Fórmula**: TP / (TP + FN)
- **Objetivo**: > 75%
- **Importancia**: No dejar pasar amenazas

### F1-Score
- **Definición**: Balance entre precision y recall
- **Fórmula**: 2 * (Precision * Recall) / (Precision + Recall)
- **Objetivo**: > 80%

### Confusion Matrix
```
                Predicho Normal    Predicho Malicioso
Real Normal          TN                  FP
Real Malicioso       FN                  TP
```

- **TN** (True Negative): Normal correctamente identificado ✅
- **TP** (True Positive): Malicioso correctamente identificado ✅
- **FP** (False Positive): Normal identificado como malicioso ❌
- **FN** (False Negative): Malicioso identificado como normal ❌

---

## 🖥️ Interfaz Web

### Página 1: Entrenamiento del Modelo (`/ml-training`)

#### Sección: Estado del Modelo
- ✅ Modelo entrenado / ⚠️ No entrenado
- Tipo de modelo (Random Forest)
- Número de árboles
- Características utilizadas
- Anomaly detection activo

#### Sección: Datos de Entrenamiento
- Total de eventos disponibles
- Eventos maliciosos vs normales
- Balance de datos (barra visual)

#### Sección: Rendimiento
- **Accuracy** (en grande)
- Precision
- Recall

#### Sección: Configuración
- **Días de datos**: Cuántos días históricos usar (default: 30)
- **Test size**: % de datos para prueba (default: 20%)
- **Random state**: Semilla para reproducibilidad (default: 42)

#### Sección: Progreso
- Barra de progreso visual
- Logs en tiempo real del entrenamiento

#### Sección: Resultados
- **Matriz de confusión** (visual 2x2)
- **Métricas por clase** (Normal y Malicioso)
- **Top 15 características** más importantes

### Página 2: Sugerencias ML (`/ml-suggestions`)

#### Filtros:
- **Confianza mínima**: 50%, 60%, 70%, 80%, 90%
- **Horas atrás**: Analizar últimas N horas
- **Acción recomendada**: Todas / Bloquear / Monitorear

#### Resumen:
- Total IPs sospechosas
- IPs con alta confianza (>80%)
- Total de anomalías detectadas
- IPs ya bloqueadas

#### Tabla de Sugerencias:
Por cada IP sospechosa muestra:
- **IP**: Dirección IP
- **Confianza ML**: % de confianza (con barra visual)
- **Eventos**: Total / Sospechosos
- **Anomalías**: Cantidad detectada
- **País**: Origen geográfico
- **Estado**: Bloqueada / Activa
- **Recomendación**: BLOQUEAR / MONITOREAR
- **Acciones**: Bloquear, Analizar

#### Modal de Detalles:
Al hacer clic en una IP:
- Confianza ML
- Recomendación del modelo
- Total de eventos
- Eventos sospechosos
- Anomalías
- País
- **Razones del modelo** (explicación detallada)
- Primera y última detección
- Estado actual

**Acciones disponibles:**
- 🚫 **Bloquear IP**: Bloquear por 24h
- 🔍 **Análisis Completo**: Ver análisis detallado
- 👁️ **Ignorar**: Agregar a whitelist (falso positivo)

#### Auto-refresh:
- Actualización automática cada 60 segundos
- Countdown visible

---

## 🔧 API Endpoints

### POST `/api/ml/train`
Entrenar el modelo ML

**Request:**
```json
{
  "days_back": 30,
  "test_size": 0.2,
  "random_state": 42
}
```

**Response:**
```json
{
  "success": true,
  "accuracy": 0.92,
  "confusion_matrix": [[850, 50], [30, 70]],
  "classification_report": {...},
  "feature_importance": [...],
  "training_samples": 800,
  "test_samples": 200,
  "malicious_ratio": 0.12
}
```

### GET `/api/ml/model-info`
Obtener información del modelo

**Response:**
```json
{
  "is_trained": true,
  "model_type": "Random Forest Classifier",
  "n_estimators": 100,
  "features_count": 20,
  "feature_importance": [...],
  "has_anomaly_detector": true
}
```

### POST `/api/ml/predict`
Predecir si un evento es malicioso

**Request:**
```json
{
  "timestamp": "2025-11-16T20:00:00",
  "severity": "high",
  "source_ip": "1.2.3.4",
  "attack_vector": "sql_injection",
  "request_method": "GET",
  "request_path": "/admin.php?id=1' OR '1'='1",
  "user_agent": "sqlmap/1.0"
}
```

**Response:**
```json
{
  "is_suspicious": true,
  "confidence": 0.89,
  "is_anomaly": true,
  "anomaly_score": -0.12,
  "probability_malicious": 0.89,
  "probability_normal": 0.11,
  "reason": "El modelo clasifica este tráfico como MALICIOSO con 89% de confianza | Detectado como ANOMALÍA | Severidad alta detectada | Caracteres sospechosos en URL (5)"
}
```

### GET `/api/ml/suggestions`
Obtener sugerencias de IPs sospechosas

**Query Params:**
- `min_confidence`: 0.6 (default)
- `hours_back`: 24 (default)

**Response:**
```json
{
  "model_trained": true,
  "suggestions": [
    {
      "ip_address": "1.2.3.4",
      "ml_confidence": 0.89,
      "total_events": 45,
      "suspicious_events": 40,
      "anomaly_events": 12,
      "country": "Unknown",
      "first_seen": "2025-11-16T10:00:00",
      "last_seen": "2025-11-16T20:00:00",
      "reasons": "El modelo clasifica...",
      "is_blocked": false,
      "recommended_action": "block"
    }
  ],
  "total": 5
}
```

---

## 📂 Archivos del Sistema

### Código:
```
modules/ml_detector.py          # Módulo principal ML (500+ líneas)
```

### Templates:
```
templates/ml_training.html      # Página de entrenamiento (600+ líneas)
templates/ml_suggestions.html   # Página de sugerencias (700+ líneas)
```

### Modelos guardados:
```
models/
├── rf_classifier.pkl           # Random Forest entrenado
├── scaler.pkl                  # StandardScaler para normalización
├── anomaly_detector.pkl        # Isolation Forest
├── label_encoders.pkl          # Encoders para features categóricas
└── feature_names.json          # Nombres de las características
```

---

## 🚀 Cómo Usar

### Paso 1: Entrenar el Modelo

1. Ir a **Machine Learning → Entrenar Modelo**
2. Configurar parámetros (o dejar por defecto)
3. Click en **"Entrenar Modelo"**
4. Esperar a que complete (puede tardar 1-2 minutos)
5. Revisar métricas:
   - ✅ Accuracy > 85% → Buen modelo
   - ⚠️ Accuracy < 75% → Necesitas más datos

**Nota**: Necesitas al menos **50 eventos** para entrenar.

### Paso 2: Ver Sugerencias

1. Ir a **Machine Learning → Sugerencias ML**
2. Configurar filtros (confianza mínima, horas)
3. Revisar tabla de IPs sospechosas
4. Para cada IP sospechosa:
   - **Confianza > 80%** → Revisar y probablemente bloquear
   - **Confianza 60-80%** → Monitorear más tiempo
   - **Confianza < 60%** → Probablemente falso positivo

### Paso 3: Tomar Acción

**Opción A: Bloquear**
- Click en botón "Bloquear"
- Confirmar
- IP bloqueada por 24 horas

**Opción B: Analizar Más**
- Click en botón "Analizar"
- Ver análisis completo de IP
- Decidir basado en más información

**Opción C: Ignorar (Falso Positivo)**
- Click en botón "Ignorar"
- IP agregada a whitelist
- ML no volverá a sugerirla

---

## 🎓 Mejores Prácticas

### 1. Re-entrenar Periódicamente
- ✅ Entrenar cada **7 días**
- ✅ Después de bloquear muchas IPs nuevas
- ✅ Cuando cambian patrones de ataque
- ✅ Si accuracy baja de 80%

### 2. Validar Sugerencias
- ❌ NO bloquear automáticamente basado en ML
- ✅ Revisar análisis completo de IP
- ✅ Ver historial de eventos
- ✅ Verificar geo-localización
- ✅ Confirmar con threat intelligence

### 3. Ajustar Umbrales
- **Ambiente productivo**: min_confidence = 0.8 (conservador)
- **Ambiente de pruebas**: min_confidence = 0.6 (más agresivo)
- **Investigación**: min_confidence = 0.5 (ver todo)

### 4. Reportar Falsos Positivos
- Si ML sugiere una IP legítima:
  - Agregar a whitelist
  - Esto mejora futuros entrenamientos

### 5. Monitorear Feature Importance
- Ver qué características son más importantes
- Si una característica tiene 0% importance, considerar removerla
- Las más importantes suelen ser:
  - Severidad
  - Caracteres sospechosos
  - Vector de ataque
  - Hora del día

---

## 📈 Casos de Uso

### Caso 1: Detectar Campañas de Ataque
**Problema**: Un botnet está atacando con IPs que rotan
**Solución**:
- ML detecta el patrón común (user agent, hora, paths)
- Sugiere todas las IPs del botnet
- Aunque sean IPs nuevas

### Caso 2: Identificar Ataques 0-Day
**Problema**: Ataque nuevo que las reglas no detectan
**Solución**:
- Isolation Forest detecta comportamiento anómalo
- ML sugiere la IP aunque no haya reglas específicas
- Permite respuesta temprana

### Caso 3: Reducir Falsos Positivos
**Problema**: Reglas estáticas bloquean tráfico legítimo
**Solución**:
- ML aprende de datos históricos
- Distingue entre tráfico legítimo inusual y ataques reales
- Sugiere solo cuando hay alta confianza

### Caso 4: Priorizar Investigación
**Problema**: Demasiadas alertas, no sabes cuáles revisar primero
**Solución**:
- ML ordena por nivel de confianza
- Investigas primero las de 90%+ confianza
- Ahorras tiempo enfocándote en amenazas reales

---

## ⚠️ Limitaciones

### 1. Requiere Datos Históricos
- ❌ No funciona sin datos previos
- ✅ Necesitas al menos 50 eventos
- ✅ Mejor con 500+ eventos
- ✅ Óptimo con 5000+ eventos

### 2. Calidad de Datos
- Si datos históricos tienen errores → Modelo aprende mal
- Si nunca bloqueaste IPs maliciosas → No hay etiquetas
- Si bloqueaste IPs legítimas → Modelo aprende falsos positivos

### 3. Ataques Totalmente Nuevos
- ML es bueno pero no perfecto
- Ataques MUY diferentes pueden pasar desapercibidos
- Por eso se combina con reglas estáticas

### 4. No Reemplaza al Humano
- ML sugiere, tú decides
- Siempre revisa antes de bloquear
- Usa tu criterio de seguridad

---

## 🔮 Futuras Mejoras

### 1. Deep Learning
- **LSTM/GRU** para secuencias temporales
- **CNN** para patrones en URLs
- **Autoencoders** para detección de anomalías

### 2. Online Learning
- Modelo se actualiza automáticamente con nuevos datos
- No necesita re-entrenamiento manual

### 3. Explicabilidad Avanzada
- **SHAP values** para explicar cada predicción
- **LIME** para interpretabilidad local
- Gráficos de decisión

### 4. Feedback Loop
- Botón "Correcta/Incorrecta" en sugerencias
- Modelo aprende de tus decisiones
- Mejora continua automática

### 5. Ensemble Models
- Combinar múltiples modelos
- Voting classifier
- Stacking

---

## 📊 Ejemplo Real

### Escenario:
IP `45.76.123.45` hace 100 peticiones en 5 minutos

### Eventos Detectados:
- 80 peticiones con SQL injection
- 15 peticiones con XSS
- 5 peticiones normales

### Características Extraídas:
```
hour: 3 (madrugada)
day_of_week: 2 (miércoles)
is_weekend: 0
is_night: 1 ✓ (sospechoso)
severity_level: 4 (critical) ✓
attack_vector: sql_injection ✓
path_length: 145 ✓ (URL larga)
suspicious_chars: 12 ✓ (muchos caracteres sospechosos)
is_bot: 1 ✓ (user agent: sqlmap)
```

### Predicción ML:
```json
{
  "is_suspicious": true,
  "confidence": 0.95,
  "is_anomaly": true,
  "reason": "El modelo clasifica este tráfico como MALICIOSO con 95% de confianza | Detectado como ANOMALÍA | Severidad alta detectada | Caracteres sospechosos en URL (12) | Tráfico nocturno (horario inusual)"
}
```

### Sugerencia Final:
```
IP: 45.76.123.45
Confianza ML: 95%
Total Eventos: 100
Eventos Sospechosos: 95
Anomalías: 85
Recomendación: BLOQUEAR
```

### Acción del Administrador:
1. Revisa la sugerencia (95% confianza → alta prioridad)
2. Ve análisis completo de IP
3. Confirma que es sqlmap
4. **Bloquea la IP**
5. ML aprende que esta decisión fue correcta

---

## ✅ Conclusión

El sistema ML proporciona una **capa adicional de inteligencia** que:

1. ✅ **Aprende** de tus datos históricos
2. ✅ **Detecta** patrones complejos
3. ✅ **Sugiere** IPs sospechosas con explicaciones
4. ✅ **Prioriza** amenazas por nivel de confianza
5. ✅ **No interfiere** con operación normal (solo sugiere)
6. ✅ **Mejora con el tiempo** (re-entrenar periódicamente)

**No reemplaza las reglas de seguridad**, las **complementa** proporcionando inteligencia adicional basada en patrones aprendidos de tus datos específicos.

---

**Fecha de Implementación:** 16 de Noviembre, 2025
**Versión:** 1.0.0
**Estado:** PRODUCCIÓN READY ✅
