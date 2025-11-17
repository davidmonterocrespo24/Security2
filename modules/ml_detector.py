"""
Módulo de Machine Learning para Detección de Tráfico Malicioso
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


class MLTrafficDetector:
    def __init__(self, db_manager, model_path='models/'):
        self.db = db_manager
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.anomaly_detector = None
        self.label_encoders = {}
        self.feature_names = []

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

        # Si no hay suficientes eventos, importar logs históricos automáticamente
        if df is None or len(df) < 50:
            print("\n⚠️  No hay suficientes eventos para entrenar.")
            print("📥 Importando logs históricos automáticamente...\n")

            imported_count = self._auto_import_historical_logs()

            if imported_count > 0:
                print(f"\n✅ Se importaron {imported_count} eventos desde logs históricos")
                print("🔄 Reintentando preparación de datos...\n")

                # Reintentar preparar datos
                df, labels = self.prepare_training_data()

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

        return {
            'is_suspicious': bool(prediction == 1),
            'confidence': confidence,
            'reason': reason,
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'probability_malicious': confidence,
            'probability_normal': float(probability[0]) if len(probability) > 1 else 0.5
        }

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

    def get_suspicious_ips(self, hours_back=24, min_confidence=0.6):
        """Obtener IPs sospechosas según el modelo ML"""
        if self.model is None:
            return []

        # Obtener eventos recientes
        events = self.db.get_security_events(limit=1000)

        # Agrupar por IP
        ip_events = {}
        for event in events:
            ip = event.get('source_ip')
            if not ip:
                continue

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
                # Obtener geo info si está disponible
                geo_info = None
                country = 'Unknown'
                for event in events_list:
                    if event.get('country'):
                        country = event['country']
                        break

                suspicious_ips.append({
                    'ip_address': ip,
                    'ml_confidence': float(avg_confidence),
                    'total_events': len(events_list),
                    'suspicious_events': suspicious_count,
                    'anomaly_events': anomaly_count,
                    'country': country,
                    'first_seen': events_list[0].get('timestamp'),
                    'last_seen': events_list[-1].get('timestamp'),
                    'reasons': predictions[0]['reason'] if predictions else 'No reason',
                    'is_blocked': self.db.is_ip_blocked(ip),
                    'recommended_action': 'block' if avg_confidence > 0.8 else 'monitor'
                })

        # Ordenar por confianza
        suspicious_ips.sort(key=lambda x: x['ml_confidence'], reverse=True)

        return suspicious_ips

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
