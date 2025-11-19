"""
Módulo de Machine Learning para Detección de Tráfico Malicioso
Con mejoras de explicabilidad (SHAP), análisis conductual y scoring de amenazas
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import json
import os

# SHAP para explicaciones de modelo
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    print("[WARN] SHAP no disponible. Instala con: pip install shap")


class MLTrafficDetector:
    def __init__(self, db_manager, model_path='models/', geo_service=None):
        self.db = db_manager
        self.model_path = model_path
        self.geo_service = geo_service
        self.model = None
        self.scaler = None
        self.anomaly_detector = None
        self.label_encoders = {}
        self.feature_names = []

        # Inicializar sistema de alertas
        self.alert_manager = None
        try:
            from modules.alert_manager import AlertManager
            self.alert_manager = AlertManager(db_manager)
        except Exception as e:
            print(f"Advertencia: No se pudo inicializar AlertManager: {e}")

        # Crear directorio de modelos si no existe
        os.makedirs(model_path, exist_ok=True)

        # Cargar modelo si existe
        self.load_model()

    def extract_features(self, events_data):
        """Extraer características de los eventos para el modelo"""
        features_list = []

        for event in events_data:
            features = {}

            # 1. Características temporales
            timestamp = event.get('timestamp')
            if timestamp:
                dt = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp
                features['hour'] = dt.hour
                features['day_of_week'] = dt.weekday()
                features['is_weekend'] = 1 if dt.weekday() >= 5 else 0
                features['is_night'] = 1 if (dt.hour >= 22 or dt.hour <= 6) else 0
            else:
                features['hour'] = 0
                features['day_of_week'] = 0
                features['is_weekend'] = 0
                features['is_night'] = 0

            # 2. Características de severidad
            severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            features['severity_level'] = severity_map.get(event.get('severity', 'low'), 1)

            # 3. Características de tipo de ataque
            attack_vector = event.get('attack_vector', 'unknown')
            features['attack_vector'] = attack_vector

            # 4. Características del evento
            features['event_type'] = event.get('event_type', 'unknown')

            # 5. Características de la IP
            ip = event.get('source_ip', '0.0.0.0')
            features['source_ip'] = ip

            # 6. Características de petición HTTP
            method = event.get('request_method', 'GET')
            features['request_method'] = method

            path = event.get('request_path', '/')
            features['path_length'] = len(path)
            features['has_query_string'] = 1 if '?' in path else 0
            features['suspicious_chars'] = sum(1 for c in path if c in ['<', '>', '"', "'", ';', '|', '&'])

            # 7. User Agent
            user_agent = event.get('user_agent', '')
            features['ua_length'] = len(user_agent)
            features['is_bot'] = 1 if any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider']) else 0

            # 8. Características de geo-localización (si están disponibles)
            features['country'] = event.get('country', 'unknown')

            # 9. NUEVO: Características de Zeek (análisis de red profundo)
            try:
                from modules.zeek_ml_integration import ZeekMLIntegration
                zeek_integration = ZeekMLIntegration(self.db)
                zeek_features = zeek_integration.extract_zeek_features_for_ip(ip, hours_back=24)

                # Agregar las 18 características de Zeek
                features['zeek_connections_count'] = zeek_features['zeek_connections_count']
                features['zeek_unique_dest_ports'] = zeek_features['zeek_unique_dest_ports']
                features['zeek_unique_dest_ips'] = zeek_features['zeek_unique_dest_ips']
                features['zeek_bytes_sent'] = zeek_features['zeek_bytes_sent']
                features['zeek_bytes_received'] = zeek_features['zeek_bytes_received']
                features['zeek_packets_sent'] = zeek_features['zeek_packets_sent']
                features['zeek_packets_received'] = zeek_features['zeek_packets_received']
                features['zeek_avg_duration'] = zeek_features['zeek_avg_duration']
                features['zeek_failed_connections'] = zeek_features['zeek_failed_connections']
                features['zeek_dns_queries'] = zeek_features['zeek_dns_queries']
                features['zeek_unique_domains'] = zeek_features['zeek_unique_domains']
                features['zeek_failed_dns'] = zeek_features['zeek_failed_dns']
                features['zeek_http_requests'] = zeek_features['zeek_http_requests']
                features['zeek_http_methods_diversity'] = zeek_features['zeek_http_methods_diversity']
                features['zeek_suspicious_user_agents'] = zeek_features['zeek_suspicious_user_agents']
                features['zeek_ssl_connections'] = zeek_features['zeek_ssl_connections']
                features['zeek_ssl_invalid_certs'] = zeek_features['zeek_ssl_invalid_certs']
                features['zeek_connection_regularity'] = zeek_features['zeek_connection_regularity']
            except Exception as e:
                # Si falla la integración de Zeek, usar valores por defecto (ceros)
                features['zeek_connections_count'] = 0
                features['zeek_unique_dest_ports'] = 0
                features['zeek_unique_dest_ips'] = 0
                features['zeek_bytes_sent'] = 0
                features['zeek_bytes_received'] = 0
                features['zeek_packets_sent'] = 0
                features['zeek_packets_received'] = 0
                features['zeek_avg_duration'] = 0.0
                features['zeek_failed_connections'] = 0
                features['zeek_dns_queries'] = 0
                features['zeek_unique_domains'] = 0
                features['zeek_failed_dns'] = 0
                features['zeek_http_requests'] = 0
                features['zeek_http_methods_diversity'] = 0
                features['zeek_suspicious_user_agents'] = 0
                features['zeek_ssl_connections'] = 0
                features['zeek_ssl_invalid_certs'] = 0
                features['zeek_connection_regularity'] = 0.0

            features_list.append(features)

        return pd.DataFrame(features_list)

    def prepare_training_data(self, days_back=30):
        """Preparar datos de entrenamiento desde la base de datos"""
        print(f"\n{'='*60}")
        print("PREPARACIÓN DE DATOS DE ENTRENAMIENTO")
        print(f"{'='*60}")
        print(f"Obteniendo eventos de los últimos {days_back} días...")

        # Obtener eventos de seguridad
        events = self.db.get_security_events(limit=10000)

        if not events or len(events) == 0:
            print("❌ No hay eventos suficientes para entrenar el modelo")
            return None, None

        print(f"✅ Eventos obtenidos: {len(events)}")

        # Mostrar estadísticas de eventos por tipo
        from collections import Counter
        event_types = Counter([e.get('event_type', 'unknown') for e in events])
        print(f"\n📊 Distribución por tipo de evento:")
        for event_type, count in event_types.most_common(10):
            print(f"  - {event_type}: {count} ({count/len(events)*100:.1f}%)")

        # Mostrar estadísticas de severidad
        severity_counts = Counter([e.get('severity', 'low') for e in events])
        print(f"\n🔥 Distribución por severidad:")
        for sev in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(sev, 0)
            if count > 0:
                print(f"  - {sev.upper()}: {count} ({count/len(events)*100:.1f}%)")

        # Extraer características
        print(f"\n🔧 Extrayendo características...")
        df = self.extract_features(events)
        print(f"✅ {len(df.columns)} características extraídas")

        # Crear etiqueta (label) basada en si la IP fue bloqueada
        # 1 = malicioso, 0 = normal
        labels = []
        malicious_by_block = 0
        malicious_by_severity = 0

        print(f"\n🏷️  Etiquetando eventos...")
        for event in events:
            ip = event.get('source_ip')
            severity = event.get('severity', 'low')

            # Etiquetar como malicioso si:
            # - Fue bloqueada
            # - Severidad crítica o alta
            is_blocked = self.db.is_ip_blocked(ip) if ip else False
            is_high_severity = severity in ['critical', 'high']

            if is_blocked:
                malicious_by_block += 1
            if is_high_severity:
                malicious_by_severity += 1

            label = 1 if (is_blocked or is_high_severity) else 0
            labels.append(label)

        df['label'] = labels

        print(f"\n📈 Distribución de labels (etiquetas):")
        malicious_count = sum(labels)
        normal_count = len(labels) - malicious_count
        print(f"  - Malicioso (1): {malicious_count} ({malicious_count/len(labels)*100:.1f}%)")
        print(f"    • Por IP bloqueada: {malicious_by_block}")
        print(f"    • Por severidad alta/crítica: {malicious_by_severity}")
        print(f"  - Normal (0): {normal_count} ({normal_count/len(labels)*100:.1f}%)")

        # Verificar balance
        if malicious_count < normal_count * 0.05:  # Menos del 5% son maliciosos
            print(f"\n⚠️  ADVERTENCIA: Datos muy desbalanceados!")
            print(f"   Solo {malicious_count/len(labels)*100:.1f}% son maliciosos")
            print(f"   Recomendado: al menos 10% maliciosos para buen entrenamiento")

        return df, labels

    def train_model(self, test_size=0.2, random_state=42):
        """Entrenar el modelo de clasificación"""
        print("\n" + "="*60)
        print("ENTRENAMIENTO DE MODELO ML")
        print("="*60 + "\n")

        # Preparar datos
        df, labels = self.prepare_training_data()

        # Verificar si necesitamos importar más datos
        should_import = False
        import_reason = ""

        # Caso 1: No hay suficientes eventos totales
        if df is None or len(df) < 50:
            should_import = True
            import_reason = f"pocos eventos totales ({len(df) if df is not None else 0} < 50)"
        # Caso 2: Datos muy desbalanceados (menos del 5% maliciosos)
        elif labels is not None:
            malicious_count = sum(labels)
            malicious_ratio = malicious_count / len(labels) if len(labels) > 0 else 0

            if malicious_ratio < 0.05:  # Menos del 5%
                should_import = True
                import_reason = f"datos muy desbalanceados ({malicious_ratio*100:.1f}% maliciosos < 5%)"
            elif malicious_count < 10:  # Menos de 10 eventos maliciosos
                should_import = True
                import_reason = f"muy pocos eventos maliciosos ({malicious_count} < 10)"

        # Importar logs históricos si es necesario
        if should_import:
            print(f"\n⚠️  Importación automática activada: {import_reason}")
            print("📥 Importando logs históricos automáticamente...\n")

            imported_count = self._auto_import_historical_logs()

            if imported_count > 0:
                print(f"\n✅ Se importaron {imported_count} eventos desde logs históricos")
                print("🔄 Reintentando preparación de datos...\n")

                # Reintentar preparar datos
                df, labels = self.prepare_training_data()

            # Verificar si ahora tenemos suficientes datos
            if df is None or len(df) < 50:
                return {
                    'success': False,
                    'error': f'No hay suficientes datos para entrenar (mínimo 50 eventos). Actualmente: {len(df) if df is not None else 0} eventos'
                }

        # Separar características categóricas y numéricas
        categorical_features = ['attack_vector', 'event_type', 'source_ip', 'request_method', 'country']
        numerical_features = [col for col in df.columns if col not in categorical_features + ['label']]

        # Codificar características categóricas
        print("Codificando características categóricas...")
        for col in categorical_features:
            if col in df.columns:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                self.label_encoders[col] = le

        # Separar features y labels
        X = df.drop('label', axis=1)
        y = df['label']

        self.feature_names = X.columns.tolist()

        # Verificar si hay suficiente diversidad en las clases
        unique_labels = y.unique()
        if len(unique_labels) < 2:
            print(f"\n⚠️  ADVERTENCIA: Solo hay una clase en los datos ({unique_labels[0]})")
            print("El modelo necesita ejemplos de ambas clases (Normal Y Malicioso)")
            print("Importando más logs históricos para obtener eventos maliciosos...\n")

            # Intentar importar más logs
            imported_count = self._auto_import_historical_logs()
            if imported_count > 0:
                # Reintentar preparar datos
                df, labels = self.prepare_training_data()
                X = df.drop('label', axis=1)
                y = df['label']
                unique_labels = y.unique()

            if len(unique_labels) < 2:
                return {
                    'success': False,
                    'error': f'No hay suficiente diversidad en los datos. Solo se encontró la clase: {unique_labels[0]}. Se necesitan eventos tanto normales como maliciosos para entrenar el modelo.'
                }

        # Dividir en train/test con estratificación
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        print(f"Datos de entrenamiento: {len(X_train)}")
        print(f"Datos de prueba: {len(X_test)}")

        # Normalizar características numéricas
        print("\nNormalizando características...")
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Entrenar Random Forest Classifier
        print("\nEntrenando Random Forest Classifier...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1
        )

        self.model.fit(X_train_scaled, y_train)

        # Evaluar modelo
        print("\nEvaluando modelo...")
        y_pred = self.model.predict(X_test_scaled)

        accuracy = accuracy_score(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        class_report = classification_report(y_test, y_pred, output_dict=True)

        print(f"\nACCURACY: {accuracy*100:.2f}%")
        print(f"\nMatriz de Confusión:")
        print(conf_matrix)
        print(f"\nReporte de Clasificación:")
        print(classification_report(y_test, y_pred))

        # Entrenar Isolation Forest para detección de anomalías
        print("\nEntrenando Isolation Forest (Anomaly Detection)...")
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # 10% de datos son anomalías
            random_state=random_state,
            n_jobs=-1
        )

        self.anomaly_detector.fit(X_train_scaled)

        # Obtener feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)

        print("\nTop 10 Características más importantes:")
        print(feature_importance.head(10))

        # Guardar modelo
        self.save_model()

        return {
            'success': True,
            'accuracy': float(accuracy),
            'confusion_matrix': conf_matrix.tolist(),
            'classification_report': class_report,
            'feature_importance': feature_importance.to_dict('records'),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'malicious_ratio': float(sum(y_train) / len(y_train))
        }

    def predict(self, event_data):
        """Predecir si un evento es malicioso"""
        if self.model is None or self.scaler is None:
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'reason': 'Modelo no entrenado',
                'is_anomaly': False
            }

        # Extraer características
        df = self.extract_features([event_data])

        # Codificar características categóricas
        categorical_features = ['attack_vector', 'event_type', 'source_ip', 'request_method', 'country']
        for col in categorical_features:
            if col in df.columns and col in self.label_encoders:
                le = self.label_encoders[col]
                # Manejar valores no vistos
                df[col] = df[col].apply(lambda x: x if x in le.classes_ else 'unknown')
                # Si 'unknown' no está en classes_, agregarlo
                if 'unknown' not in le.classes_:
                    le.classes_ = np.append(le.classes_, 'unknown')
                df[col] = le.transform(df[col].astype(str))

        # Asegurar que tenga todas las features
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0

        df = df[self.feature_names]

        # Normalizar
        X_scaled = self.scaler.transform(df)

        # Verificar que el modelo tenga ambas clases
        if not hasattr(self.model, 'classes_') or len(self.model.classes_) < 2:
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'reason': 'Modelo entrenado con datos insuficientes (solo una clase)',
                'is_anomaly': False
            }

        # Predicción de clasificación
        try:
            prediction = self.model.predict(X_scaled)[0]
            probability = self.model.predict_proba(X_scaled)[0]
        except Exception as e:
            return {
                'is_suspicious': False,
                'confidence': 0.0,
                'reason': f'Error en predicción: {str(e)}',
                'is_anomaly': False
            }

        # Predicción de anomalía
        anomaly_score = self.anomaly_detector.score_samples(X_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(X_scaled)[0] == -1

        # Confianza (probabilidad de la clase positiva)
        confidence = float(probability[1]) if len(probability) > 1 else 0.5

        # Generar razón
        reason = self._generate_reason(df, prediction, confidence, is_anomaly)

        result = {
            'is_suspicious': bool(prediction == 1),
            'confidence': confidence,
            'reason': reason,
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'probability_malicious': confidence,
            'probability_normal': float(probability[0]) if len(probability) > 1 else 0.5
        }

        # INTEGRACIÓN CON SISTEMA DE ALERTAS
        # Si detecta tráfico malicioso con alta confianza, disparar alerta
        if self.alert_manager and prediction == 1 and confidence >= 0.8:
            try:
                # Preparar evento para el sistema de alertas
                alert_event = {
                    'type': 'ml_prediction',
                    'severity': 'HIGH' if confidence >= 0.9 else 'MEDIUM' if confidence >= 0.8 else 'LOW',
                    'ip': event_data.get('source_ip', 'unknown'),
                    'ml_confidence': confidence,
                    'confidence': int(confidence * 100),  # Convertir a porcentaje
                    'country': event_data.get('country', 'Unknown'),
                    'reason': reason,
                    'timestamp': event_data.get('timestamp', datetime.utcnow().isoformat()),
                    'attack_vector': event_data.get('attack_vector', 'unknown'),
                    'event_type': event_data.get('event_type', 'unknown')
                }

                # Disparar alerta
                self.alert_manager.process_alert(alert_event)
            except Exception as e:
                # No fallar si hay error en alertas, solo loguearlo
                print(f"Error disparando alerta ML: {e}")

        return result

    def _generate_reason(self, features_df, prediction, confidence, is_anomaly):
        """Generar explicación de la predicción"""
        reasons = []

        if prediction == 1:
            reasons.append(f"El modelo clasifica este tráfico como MALICIOSO con {confidence*100:.1f}% de confianza")
        else:
            reasons.append(f"El modelo clasifica este tráfico como NORMAL con {(1-confidence)*100:.1f}% de confianza")

        if is_anomaly:
            reasons.append("Detectado como ANOMALÍA (comportamiento inusual)")

        # Analizar características específicas
        row = features_df.iloc[0]

        if row['severity_level'] >= 3:
            reasons.append("Severidad alta detectada")

        if row['suspicious_chars'] > 3:
            reasons.append(f"Caracteres sospechosos en URL ({row['suspicious_chars']})")

        if row['is_night'] == 1:
            reasons.append("Tráfico nocturno (horario inusual)")

        if row['path_length'] > 100:
            reasons.append(f"URL muy larga ({row['path_length']} caracteres)")

        return " | ".join(reasons)

    def get_suspicious_ips(self, hours_back=24, min_confidence=0.6, use_cache=True):
        """
        Obtener IPs sospechosas según el modelo ML
        Versión mejorada con análisis conductual, threat scoring y CACHÉ
        """
        if self.model is None:
            return []

        # Importar funciones de mejoras ML
        from modules.ml_enhancements import (
            extract_ip_behavioral_features,
            calculate_threat_score,
            generate_enhanced_reason
        )

        print(f"\n🔍 Analizando eventos de las últimas {hours_back} horas...")
        print(f"   Umbral de confianza mínimo: {min_confidence*100:.0f}%")

        # PASO 1: Intentar usar caché si está habilitado
        if use_cache:
            print("   💾 Buscando predicciones en caché...")
            try:
                cached_predictions = self.db.get_ml_predictions(
                    hours_back=hours_back,
                    min_confidence=min_confidence
                )

                if cached_predictions and len(cached_predictions) > 0:
                    print(f"   ✅ Encontradas {len(cached_predictions)} predicciones en caché")

                    # Verificar si hay IPs nuevas desde el último análisis
                    cached_ips = set(p['ip_address'] for p in cached_predictions)

                    # Obtener IPs de eventos recientes
                    events = self.db.get_security_events(limit=5000)

                    # Filtrar por tiempo
                    try:
                        if hours_back > 24 * 365:
                            days_back = hours_back / 24
                            cutoff_time = datetime.utcnow() - timedelta(days=days_back)
                        else:
                            cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
                    except OverflowError:
                        cutoff_time = datetime.utcnow() - timedelta(days=365)

                    recent_ips = set()
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
                        new_predictions = self._analyze_and_cache_ips(list(new_ips), hours_back, min_confidence)

                        # Combinar predicciones de caché + nuevas
                        all_predictions = cached_predictions + new_predictions
                        all_predictions.sort(key=lambda x: x.get('threat_score', 0), reverse=True)

                        print(f"   ✅ Total: {len(all_predictions)} IPs sospechosas (caché + nuevas)")
                        self._print_top_threats(all_predictions)
                        return all_predictions
                    else:
                        print("   ✅ No hay IPs nuevas, usando caché completo")
                        self._print_top_threats(cached_predictions)
                        return cached_predictions
            except Exception as e:
                print(f"   ⚠️  Error accediendo al caché: {e}")
                print("   🔄 Realizando análisis completo...")

        # PASO 2: Si no hay caché o está deshabilitado, análisis completo
        print("   🔄 Realizando análisis completo (sin caché)...")
        return self._perform_full_analysis(hours_back, min_confidence)

    def _perform_full_analysis(self, hours_back, min_confidence):
        """Realizar análisis completo de todas las IPs y guardar en caché"""
        from modules.ml_enhancements import (
            extract_ip_behavioral_features,
            calculate_threat_score,
            generate_enhanced_reason
        )

        # Obtener eventos recientes
        events = self.db.get_security_events(limit=5000)

        # Filtrar por tiempo
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
            timestamp = event.get('timestamp')
            if timestamp:
                if isinstance(timestamp, str):
                    event_time = datetime.fromisoformat(timestamp)
                else:
                    event_time = timestamp

                if event_time >= cutoff_time:
                    filtered_events.append(event)

        events = filtered_events
        print(f"   ✅ {len(events)} eventos encontrados en ese período")

        # Agrupar por IP
        ip_events = {}
        for event in events:
            ip = event.get('source_ip')
            if not ip:
                continue

            if ip not in ip_events:
                ip_events[ip] = []
            ip_events[ip].append(event)

        print(f"\n📊 Analizando {len(ip_events)} IPs únicas con análisis conductual...")

        # Analizar todas las IPs
        suspicious_ips = []
        for ip, events_list in ip_events.items():
            result = self._analyze_single_ip(ip, events_list, min_confidence)
            if result:
                suspicious_ips.append(result)
                # Guardar en caché
                self.db.save_ml_prediction(ip, result)

        # Ordenar por threat score
        suspicious_ips.sort(key=lambda x: x['threat_score'], reverse=True)

        print(f"\n✅ Análisis completado:")
        print(f"   - IPs sospechosas encontradas: {len(suspicious_ips)}")
        print(f"   - IPs analizadas: {len(ip_events)}")

        self._print_top_threats(suspicious_ips)

        return suspicious_ips

    def _analyze_and_cache_ips(self, ip_list, hours_back, min_confidence):
        """Analizar IPs específicas y guardar en caché"""
        from modules.ml_enhancements import (
            extract_ip_behavioral_features,
            calculate_threat_score,
            generate_enhanced_reason
        )

        # Obtener eventos
        events = self.db.get_security_events(limit=5000)

        # Filtrar por tiempo e IPs específicas
        try:
            if hours_back > 24 * 365:
                days_back = hours_back / 24
                cutoff_time = datetime.utcnow() - timedelta(days=days_back)
            else:
                cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        except OverflowError:
            cutoff_time = datetime.utcnow() - timedelta(days=365)

        # Filtrar eventos de las IPs nuevas
        ip_events = {}
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
                    if ip not in ip_events:
                        ip_events[ip] = []
                    ip_events[ip].append(event)

        # Analizar cada IP nueva
        suspicious_ips = []
        for ip, events_list in ip_events.items():
            result = self._analyze_single_ip(ip, events_list, min_confidence)
            if result:
                suspicious_ips.append(result)
                # Guardar en caché
                self.db.save_ml_prediction(ip, result)

        print(f"   ✅ {len(suspicious_ips)} nuevas IPs sospechosas analizadas y guardadas en caché")

        return suspicious_ips

    def _analyze_single_ip(self, ip, events_list, min_confidence):
        """Analizar una sola IP con mejoras ML"""
        from modules.ml_enhancements import (
            extract_ip_behavioral_features,
            calculate_threat_score,
            generate_enhanced_reason
        )

        # 1. Predecir para cada evento
        predictions = []
        for event in events_list:
            pred = self.predict(event)
            predictions.append(pred)

        # Calcular métricas agregadas
        avg_confidence = np.mean([p['confidence'] for p in predictions])
        suspicious_count = sum(1 for p in predictions if p['is_suspicious'])
        anomaly_count = sum(1 for p in predictions if p['is_anomaly'])

        # Si no supera el umbral, retornar None
        if avg_confidence < min_confidence:
            return None

        # 2. Análisis Conductual
        behavioral_features = extract_ip_behavioral_features(ip, events_list)

        # 3. Obtener información geográfica
        country = 'Unknown'
        country_code = 'XX'

        # Intentar obtener país del evento primero
        for event in events_list:
            event_country = event.get('country')
            if event_country and event_country not in ['unknown', 'Unknown', '', None]:
                country = event_country
                # Intentar obtener country_code si está disponible
                if '(' in country and ')' in country:
                    # Formato: "United States (US)"
                    country_code = country.split('(')[1].split(')')[0]
                break

        # Si no hay país en el evento, usar servicio de geolocalización
        if country == 'Unknown' and self.geo_service:
            try:
                geo_info = self.geo_service.get_country_info(ip)
                if geo_info:
                    country = f"{geo_info['country_name']} ({geo_info['country_code']})"
                    country_code = geo_info['country_code']
            except Exception as e:
                print(f"Error obteniendo geo info para {ip}: {e}")

        # Si todavía no tenemos país, intentar consultar la base de datos
        if country == 'Unknown':
            try:
                from database.models import IPGeolocation
                session = self.db.get_session()
                geo = session.query(IPGeolocation).filter_by(ip=ip).first()
                if geo and geo.country:
                    country = f"{geo.country} ({geo.country_code})" if geo.country_code else geo.country
                    country_code = geo.country_code or 'XX'
                session.close()
            except Exception as e:
                pass

        # 4. Calcular Threat Score
        threat_score_info = calculate_threat_score(
            ip_address=ip,
            ml_confidence=avg_confidence,
            behavioral_features=behavioral_features,
            country_code=country_code
        )

        # 5. Generar Razón Mejorada
        first_event_features = self.extract_features([events_list[0]])

        enhanced_reason = generate_enhanced_reason(
            features_df=first_event_features,
            prediction=1 if avg_confidence >= 0.6 else 0,
            confidence=avg_confidence,
            behavioral_features=behavioral_features,
            threat_score_info=threat_score_info
        )

        # 6. Construir resultado
        is_blocked = self.db.is_ip_blocked(ip)

        return {
            # Campos originales
            'ip_address': ip,
            'ml_confidence': float(avg_confidence),
            'total_events': len(events_list),
            'suspicious_events': suspicious_count,
            'anomaly_events': anomaly_count,
            'country': country,
            'country_code': country_code,
            'first_seen': events_list[0].get('timestamp'),
            'last_seen': events_list[-1].get('timestamp'),
            'is_blocked': is_blocked,

            # Campos NUEVOS con mejoras
            'threat_score': threat_score_info['threat_score'],
            'recommended_action': threat_score_info['action'],
            'action_text': threat_score_info['action_text'],
            'action_description': threat_score_info['action_description'],
            'threat_color': threat_score_info['color'],
            'threat_priority': threat_score_info['priority'],
            'threat_factors': threat_score_info['factors'],
            'threat_factors_count': threat_score_info['factors_count'],

            # Razón mejorada
            'reasons': enhanced_reason,

            # Características conductuales
            'behavioral_features': behavioral_features,
            'requests_per_minute': behavioral_features['requests_per_minute'],
            'error_ratio': behavioral_features['error_ratio'],
            'is_bot': behavioral_features['is_rhythmic_bot'],
            'escalation_ratio': behavioral_features['escalation_ratio']
        }

    def _print_top_threats(self, suspicious_ips):
        """Imprimir top 5 amenazas en consola"""
        if suspicious_ips and len(suspicious_ips) > 0:
            print(f"\n🎯 Top 5 IPs más peligrosas (por Threat Score):")
            for idx, ip_info in enumerate(suspicious_ips[:5], 1):
                score = ip_info.get('threat_score', 0)
                action = ip_info.get('action_text', '')
                print(f"   {idx}. {ip_info['ip_address']} - Score: {score}/100 {action}")
                print(f"      ML: {ip_info['ml_confidence']*100:.1f}% | Eventos: {ip_info['total_events']} | {ip_info.get('requests_per_minute', 0):.1f} req/min")

    def save_model(self):
        """Guardar modelo entrenado"""
        try:
            # Guardar modelo de clasificación
            joblib.dump(self.model, os.path.join(self.model_path, 'rf_classifier.pkl'))

            # Guardar scaler
            joblib.dump(self.scaler, os.path.join(self.model_path, 'scaler.pkl'))

            # Guardar detector de anomalías
            joblib.dump(self.anomaly_detector, os.path.join(self.model_path, 'anomaly_detector.pkl'))

            # Guardar label encoders
            joblib.dump(self.label_encoders, os.path.join(self.model_path, 'label_encoders.pkl'))

            # Guardar feature names
            with open(os.path.join(self.model_path, 'feature_names.json'), 'w') as f:
                json.dump(self.feature_names, f)

            print(f"\nModelo guardado en: {self.model_path}")
            return True
        except Exception as e:
            print(f"Error guardando modelo: {e}")
            return False

    def load_model(self):
        """Cargar modelo previamente entrenado"""
        try:
            model_file = os.path.join(self.model_path, 'rf_classifier.pkl')

            if not os.path.exists(model_file):
                print("No se encontró modelo entrenado")
                return False

            # Cargar modelo
            self.model = joblib.load(model_file)

            # Cargar scaler
            self.scaler = joblib.load(os.path.join(self.model_path, 'scaler.pkl'))

            # Cargar detector de anomalías
            self.anomaly_detector = joblib.load(os.path.join(self.model_path, 'anomaly_detector.pkl'))

            # Cargar label encoders
            self.label_encoders = joblib.load(os.path.join(self.model_path, 'label_encoders.pkl'))

            # Cargar feature names
            with open(os.path.join(self.model_path, 'feature_names.json'), 'r') as f:
                self.feature_names = json.load(f)

            print(f"Modelo cargado desde: {self.model_path}")
            return True
        except Exception as e:
            print(f"Error cargando modelo: {e}")
            return False

    def get_model_info(self):
        """Obtener información del modelo"""
        if self.model is None:
            return {
                'is_trained': False,
                'message': 'Modelo no entrenado'
            }

        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)

        return {
            'is_trained': True,
            'model_type': 'Random Forest Classifier',
            'n_estimators': self.model.n_estimators,
            'features_count': len(self.feature_names),
            'feature_importance': feature_importance.head(10).to_dict('records'),
            'has_anomaly_detector': self.anomaly_detector is not None
        }

    def _auto_import_historical_logs(self):
        """Importar logs históricos automáticamente para entrenamiento"""
        from modules.log_analyzer import LogAnalyzer

        # Crear analizador de logs
        log_analyzer = LogAnalyzer(self.db)

        # Detectar logs disponibles
        available_logs = log_analyzer.get_available_log_files()

        if not available_logs:
            print("❌ No se encontraron archivos de logs en el sistema")
            return 0

        print(f"📁 Encontrados {len(available_logs)} archivos de logs:")
        for log_type, info in available_logs.items():
            size_mb = info['size'] / (1024 * 1024)
            print(f"   - {log_type}: {info['path']} ({size_mb:.2f} MB)")

        # Importar logs por lotes (límite de 50000 líneas por archivo)
        total_imported = 0

        for log_type, info in available_logs.items():
            log_path = info['path']
            print(f"\n📥 Importando {log_type} desde {log_path}...")

            try:
                if 'nginx_access' in log_type:
                    result = log_analyzer.import_nginx_access_logs(log_path, limit=50000)
                elif 'ssh' in log_type:
                    result = log_analyzer.import_ssh_auth_logs(log_path, limit=50000)
                elif 'fail2ban' in log_type:
                    result = log_analyzer.import_fail2ban_logs(log_path, limit=50000)
                else:
                    continue

                if result.get('success'):
                    events_created = result.get('events_created', 0)
                    total_imported += events_created
                    print(f"   ✅ {events_created} eventos creados")

                    # Mostrar IPs sospechosas detectadas
                    if result.get('suspicious_ips'):
                        print(f"   🔍 {len(result['suspicious_ips'])} IPs sospechosas detectadas")

                    if result.get('brute_force_ips'):
                        print(f"   ⚠️  {len(result['brute_force_ips'])} IPs con brute force detectadas")
                        # Auto-bloquear IPs con brute force crítico
                        for bf_ip in result['brute_force_ips'][:5]:  # Top 5
                            if bf_ip['failed_attempts'] >= 10:
                                try:
                                    self.db.block_ip(
                                        ip_address=bf_ip['ip'],
                                        reason=f"Auto-bloqueado: {bf_ip['failed_attempts']} intentos SSH fallidos (detectado en logs históricos)",
                                        blocked_by='ml_auto',
                                        duration_hours=48
                                    )
                                    print(f"   🚫 IP {bf_ip['ip']} bloqueada automáticamente ({bf_ip['failed_attempts']} intentos)")
                                except:
                                    pass

                    if result.get('repeat_offenders'):
                        print(f"   🔁 {len(result['repeat_offenders'])} IPs reincidentes detectadas (Fail2ban)")
                        # Auto-bloquear IPs reincidentes de Fail2ban
                        for offender in result['repeat_offenders'][:5]:
                            if offender['bans'] >= 3:
                                try:
                                    self.db.block_ip(
                                        ip_address=offender['ip'],
                                        reason=f"Auto-bloqueado: {offender['bans']} bans por Fail2ban en jails: {', '.join(offender['jails'][:3])}",
                                        blocked_by='ml_auto',
                                        duration_hours=72
                                    )
                                    print(f"   🚫 IP {offender['ip']} bloqueada automáticamente ({offender['bans']} bans)")
                                except:
                                    pass
                else:
                    print(f"   ❌ Error: {result.get('error', 'Unknown error')}")

            except Exception as e:
                print(f"   ❌ Error importando {log_type}: {str(e)}")
                continue

        return total_imported

    def process_with_auto_blocker(self, auto_blocker, hours_back=24, min_confidence=0.6, dry_run=False):
        """
        Procesar predicciones ML con el sistema de auto-bloqueo

        Args:
            auto_blocker: Instancia de AutoBlocker
            hours_back: Horas hacia atrás para analizar
            min_confidence: Confianza mínima para considerar una IP (0.0 - 1.0)
            dry_run: Si es True, solo evalúa sin bloquear

        Returns:
            dict: Resultados del procesamiento
        """
        print(f"\n{'='*70}")
        print("PROCESAMIENTO ML CON AUTO-BLOQUEO")
        print(f"{'='*70}")
        print(f"Modo: {'DRY-RUN (Prueba)' if dry_run else 'PRODUCCIÓN (Bloqueará IPs)'}")
        print(f"Período: últimas {hours_back} horas")
        print(f"Confianza mínima: {min_confidence*100:.0f}%")

        # 1. Obtener predicciones ML
        print(f"\n[1/3] Obteniendo predicciones ML...")
        suspicious_ips = self.get_suspicious_ips(
            hours_back=hours_back,
            min_confidence=min_confidence,
            use_cache=True
        )

        if not suspicious_ips or len(suspicious_ips) == 0:
            print(f"\n✅ No se encontraron IPs sospechosas por encima del umbral {min_confidence*100:.0f}%")
            return {
                'success': True,
                'evaluated': 0,
                'blocked': 0,
                'already_blocked': 0,
                'whitelisted': 0,
                'below_threshold': 0,
                'dry_run': dry_run,
                'message': 'No hay IPs sospechosas para procesar'
            }

        print(f"✅ {len(suspicious_ips)} IPs sospechosas encontradas")

        # 2. Convertir al formato esperado por auto_blocker
        print(f"\n[2/3] Preparando predicciones para auto-blocker...")
        predictions_data = []

        for ip_info in suspicious_ips:
            # Mapear severity usando threat_score
            threat_score = ip_info.get('threat_score', 0)
            if threat_score >= 90:
                severity = 'critical'
            elif threat_score >= 70:
                severity = 'high'
            elif threat_score >= 50:
                severity = 'medium'
            else:
                severity = 'low'

            prediction = {
                'ip_address': ip_info['ip_address'],
                'ml_confidence': ip_info['ml_confidence'],
                'threat_score': threat_score,
                'severity': severity,
                'event_count': ip_info.get('total_events', 0),
                'first_seen': ip_info.get('first_seen'),
                'last_seen': ip_info.get('last_seen'),
                'country': ip_info.get('country', 'Unknown'),
                'reasons': ip_info.get('reasons', ''),
                'behavioral_features': ip_info.get('behavioral_features', {}),
                'recommended_action': ip_info.get('recommended_action', 'monitor')
            }
            predictions_data.append(prediction)

        print(f"✅ {len(predictions_data)} predicciones preparadas")

        # 3. Procesar con auto-blocker
        print(f"\n[3/3] Procesando con auto-blocker...")
        results = auto_blocker.process_ml_predictions(predictions_data, dry_run=dry_run)

        # Mostrar resumen
        print(f"\n{'='*70}")
        print("RESULTADOS DEL PROCESAMIENTO")
        print(f"{'='*70}")
        print(f"IPs evaluadas: {results['evaluated']}")
        print(f"IPs bloqueadas: {results['blocked']}" if not dry_run else f"IPs a bloquear: {results['blocked']}")
        print(f"Ya bloqueadas: {results['already_blocked']}")
        print(f"En whitelist: {results['whitelisted']}")
        print(f"Bajo umbral: {results['below_threshold']}")

        if dry_run:
            print(f"\n⚠️  MODO DRY-RUN: Ninguna IP fue bloqueada realmente")
            print(f"   Activa el modo producción para bloquear las IPs detectadas")
        else:
            print(f"\n✅ Procesamiento completado en modo PRODUCCIÓN")
            if results['blocked'] > 0:
                print(f"   {results['blocked']} IPs fueron bloqueadas automáticamente")

        print(f"{'='*70}\n")

        results['dry_run'] = dry_run
        return results
