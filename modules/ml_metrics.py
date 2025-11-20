"""
Módulo de Métricas del Modelo ML
Sistema de monitoreo y evaluación del rendimiento del modelo de Machine Learning
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, precision_recall_curve,
    classification_report
)
import json


class MLMetrics:
    """
    Gestor de métricas del modelo ML
    Calcula, almacena y reporta métricas de rendimiento
    """

    def __init__(self, db_manager, ml_detector):
        """
        Inicializar gestor de métricas

        Args:
            db_manager: Instancia de DatabaseManager
            ml_detector: Instancia de MLTrafficDetector
        """
        self.db = db_manager
        self.ml_detector = ml_detector

    def evaluate_model(self, test_data=None, test_labels=None):
        """
        Evaluar el modelo ML con datos de prueba

        Args:
            test_data: Datos de prueba (si None, usa datos recientes de BD)
            test_labels: Etiquetas reales (si None, usa eventos bloqueados)

        Returns:
            dict: Métricas calculadas
        """
        print("\n" + "="*70)
        print("EVALUACIÓN DEL MODELO ML")
        print("="*70)

        # Si no hay datos de prueba, obtener de la BD
        if test_data is None or test_labels is None:
            print("\n[1/5] Obteniendo datos de validación de la base de datos...")
            test_data, test_labels = self._get_validation_data()

            if len(test_data) == 0:
                print("  [WARN] No hay datos suficientes para evaluación")
                return {
                    'error': 'Insuficientes datos de validación',
                    'samples': 0
                }

        print(f"  [OK] {len(test_data)} muestras para evaluación")

        # Verificar que el modelo está entrenado
        if not self.ml_detector.model:
            print("\n  [ERROR] Modelo no entrenado")
            return {'error': 'Modelo no entrenado', 'samples': 0}

        # Hacer predicciones
        print("\n[2/5] Generando predicciones...")
        try:
            predictions = self.ml_detector.model.predict(test_data)
            probabilities = self.ml_detector.model.predict_proba(test_data)[:, 1]
            print(f"  [OK] Predicciones generadas")
        except Exception as e:
            print(f"  [ERROR] Error al predecir: {e}")
            return {'error': str(e), 'samples': len(test_data)}

        # Calcular métricas básicas
        print("\n[3/5] Calculando métricas de clasificación...")
        metrics = self._calculate_classification_metrics(test_labels, predictions, probabilities)
        print(f"  [OK] Métricas calculadas")
        print(f"       Accuracy: {metrics['accuracy']:.2%}")
        print(f"       Precision: {metrics['precision']:.2%}")
        print(f"       Recall: {metrics['recall']:.2%}")
        print(f"       F1-Score: {metrics['f1_score']:.2%}")

        # Calcular matriz de confusión
        print("\n[4/5] Calculando matriz de confusión...")
        cm = confusion_matrix(test_labels, predictions)
        metrics['confusion_matrix'] = cm.tolist()
        metrics['confusion_matrix_labels'] = {
            'tn': int(cm[0, 0]),  # True Negatives
            'fp': int(cm[0, 1]),  # False Positives
            'fn': int(cm[1, 0]),  # False Negatives
            'tp': int(cm[1, 1])   # True Positives
        }
        print(f"  [OK] Matriz de confusión calculada")

        # Calcular curvas ROC y PR
        print("\n[5/5] Calculando curvas ROC y Precision-Recall...")
        metrics['roc_curve'] = self._calculate_roc_curve(test_labels, probabilities)
        metrics['pr_curve'] = self._calculate_pr_curve(test_labels, probabilities)
        print(f"  [OK] Curvas calculadas (AUC-ROC: {metrics['roc_auc']:.3f})")

        # Información adicional
        metrics['samples_evaluated'] = len(test_data)
        metrics['evaluated_at'] = datetime.utcnow().isoformat()
        metrics['model_version'] = self._get_model_version()

        print("\n" + "="*70)
        print("[OK] EVALUACIÓN COMPLETADA")
        print("="*70 + "\n")

        return metrics

    def _get_validation_data(self):
        """
        Obtener datos de validación de la base de datos
        Usa eventos recientes con labels conocidos (bloqueados vs normales)

        Returns:
            tuple: (features, labels)
        """
        from database.models import SecurityEvent

        session = self.db.get_session()

        try:
            # Obtener eventos de los últimos 30 días
            cutoff_time = datetime.utcnow() - timedelta(days=30)

            events = session.query(SecurityEvent)\
                .filter(SecurityEvent.timestamp >= cutoff_time)\
                .all()

            if not events:
                return np.array([]), np.array([])

            # Convertir a formato del modelo
            events_data = []
            labels = []

            for event in events:
                event_dict = {
                    'timestamp': event.timestamp,
                    'severity': event.severity,
                    'attack_vector': event.attack_vector or 'unknown',
                    'source_ip': event.source_ip,
                    'event_type': event.event_type
                }
                events_data.append(event_dict)

                # Label: 1 si está bloqueado o es crítico/alto, 0 si no
                is_malicious = (
                    event.severity in ['critical', 'high'] or
                    event.is_blocked or
                    event.event_type in ['brute_force', 'port_scan', 'sql_injection', 'ddos', 'malicious_traffic'] or
                    (event.attack_vector and event.attack_vector in ['brute_force', 'port_scan', 'sql_injection', 'ddos'])
                )
                labels.append(1 if is_malicious else 0)

            # Extraer features usando el método del detector
            features = self.ml_detector.extract_features(events_data)

            # Convertir a array numpy
            if features is not None and len(features) > 0:
                # Si es lista de diccionarios, convertir a DataFrame
                if isinstance(features, list):
                    df_features = pd.DataFrame(features)
                else:
                    df_features = features

                # Seleccionar solo columnas numéricas
                X = df_features.select_dtypes(include=[np.number]).values
                y = np.array(labels)

                if len(X) > 0 and len(y) > 0:
                    return X, y
                else:
                    return np.array([]), np.array([])
            else:
                return np.array([]), np.array([])

        finally:
            session.close()

    def _calculate_classification_metrics(self, y_true, y_pred, y_prob):
        """
        Calcular métricas de clasificación

        Args:
            y_true: Etiquetas reales
            y_pred: Predicciones del modelo
            y_prob: Probabilidades predichas

        Returns:
            dict: Métricas calculadas
        """
        metrics = {
            'accuracy': float(accuracy_score(y_true, y_pred)),
            'precision': float(precision_score(y_true, y_pred, zero_division=0)),
            'recall': float(recall_score(y_true, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_true, y_pred, zero_division=0))
        }

        # Calcular ROC AUC
        try:
            fpr, tpr, _ = roc_curve(y_true, y_prob)
            metrics['roc_auc'] = float(auc(fpr, tpr))
        except:
            metrics['roc_auc'] = 0.0

        return metrics

    def _calculate_roc_curve(self, y_true, y_prob):
        """
        Calcular curva ROC

        Args:
            y_true: Etiquetas reales
            y_prob: Probabilidades predichas

        Returns:
            dict: Datos de la curva ROC
        """
        try:
            fpr, tpr, thresholds = roc_curve(y_true, y_prob)
            roc_auc = auc(fpr, tpr)

            # Limitar puntos para el gráfico (máximo 100 puntos)
            step = max(1, len(fpr) // 100)

            return {
                'fpr': fpr[::step].tolist(),
                'tpr': tpr[::step].tolist(),
                'thresholds': thresholds[::step].tolist(),
                'auc': float(roc_auc)
            }
        except Exception as e:
            print(f"Error calculando curva ROC: {e}")
            return {
                'fpr': [0, 1],
                'tpr': [0, 1],
                'thresholds': [1, 0],
                'auc': 0.5
            }

    def _calculate_pr_curve(self, y_true, y_prob):
        """
        Calcular curva Precision-Recall

        Args:
            y_true: Etiquetas reales
            y_prob: Probabilidades predichas

        Returns:
            dict: Datos de la curva PR
        """
        try:
            precision, recall, thresholds = precision_recall_curve(y_true, y_prob)
            pr_auc = auc(recall, precision)

            # Limitar puntos
            step = max(1, len(precision) // 100)

            return {
                'precision': precision[::step].tolist(),
                'recall': recall[::step].tolist(),
                'thresholds': thresholds[::step].tolist() if len(thresholds) > 0 else [],
                'auc': float(pr_auc)
            }
        except Exception as e:
            print(f"Error calculando curva PR: {e}")
            return {
                'precision': [1, 0],
                'recall': [0, 1],
                'thresholds': [],
                'auc': 0.5
            }

    def _get_model_version(self):
        """Obtener versión del modelo actual"""
        model_info = self.ml_detector.get_model_info()
        return model_info.get('model_version', 'unknown')

    def get_feature_importance(self, top_n=20):
        """
        Obtener importancia de características

        Args:
            top_n: Número de features más importantes a retornar

        Returns:
            dict: Features con sus importancias
        """
        print("\n" + "="*70)
        print("ANÁLISIS DE FEATURE IMPORTANCE")
        print("="*70)

        if not self.ml_detector.model:
            print("  [ERROR] Modelo no entrenado")
            return {'error': 'Modelo no entrenado'}

        try:
            # Obtener importancias del modelo
            if hasattr(self.ml_detector.model, 'feature_importances_'):
                importances = self.ml_detector.model.feature_importances_
                feature_names = self.ml_detector.feature_names

                # Crear DataFrame y ordenar
                df = pd.DataFrame({
                    'feature': feature_names,
                    'importance': importances
                }).sort_values('importance', ascending=False)

                # Tomar top N
                df_top = df.head(top_n)

                print(f"\n[OK] Top {len(df_top)} características más importantes:")
                for idx, row in df_top.iterrows():
                    print(f"  {row['feature']:30s} {row['importance']:.4f}")

                print("\n" + "="*70 + "\n")

                return {
                    'features': df_top['feature'].tolist(),
                    'importances': df_top['importance'].tolist(),
                    'total_features': len(feature_names)
                }
            else:
                print("  [WARN] Modelo no soporta feature_importances_")
                return {'error': 'Modelo no soporta feature importance'}

        except Exception as e:
            print(f"  [ERROR] Error calculando importancias: {e}")
            return {'error': str(e)}

    def save_metrics(self, metrics):
        """
        Guardar métricas en la base de datos

        Args:
            metrics: Diccionario con métricas

        Returns:
            int: ID del registro guardado
        """
        try:
            from database.models import MLModelMetrics

            session = self.db.get_session()

            metric_record = MLModelMetrics(
                model_version=metrics.get('model_version', 'unknown'),
                evaluated_at=datetime.utcnow(),
                accuracy=metrics.get('accuracy', 0.0),
                precision=metrics.get('precision', 0.0),
                recall=metrics.get('recall', 0.0),
                f1_score=metrics.get('f1_score', 0.0),
                roc_auc=metrics.get('roc_auc', 0.0),
                samples_evaluated=metrics.get('samples_evaluated', 0),
                confusion_matrix=json.dumps(metrics.get('confusion_matrix', [])),
                roc_curve_data=json.dumps(metrics.get('roc_curve', {})),
                pr_curve_data=json.dumps(metrics.get('pr_curve', {})),
                extra_data=json.dumps({
                    'confusion_matrix_labels': metrics.get('confusion_matrix_labels', {}),
                })
            )

            session.add(metric_record)
            session.commit()

            metric_id = metric_record.id
            session.close()

            print(f"[OK] Métricas guardadas en BD (ID: {metric_id})")
            return metric_id

        except Exception as e:
            print(f"[ERROR] Error guardando métricas: {e}")
            return None

    def get_metrics_history(self, days_back=30, limit=50):
        """
        Obtener histórico de métricas

        Args:
            days_back: Días hacia atrás
            limit: Límite de registros

        Returns:
            list: Lista de métricas históricas
        """
        try:
            from database.models import MLModelMetrics

            session = self.db.get_session()
            cutoff_time = datetime.utcnow() - timedelta(days=days_back)

            records = session.query(MLModelMetrics)\
                .filter(MLModelMetrics.evaluated_at >= cutoff_time)\
                .order_by(MLModelMetrics.evaluated_at.desc())\
                .limit(limit)\
                .all()

            history = []
            for record in records:
                history.append({
                    'id': record.id,
                    'model_version': record.model_version,
                    'evaluated_at': record.evaluated_at.isoformat(),
                    'accuracy': record.accuracy,
                    'precision': record.precision,
                    'recall': record.recall,
                    'f1_score': record.f1_score,
                    'roc_auc': record.roc_auc,
                    'samples_evaluated': record.samples_evaluated
                })

            session.close()
            return history

        except Exception as e:
            print(f"[ERROR] Error obteniendo histórico: {e}")
            return []

    def compare_versions(self, version1, version2):
        """
        Comparar métricas entre dos versiones del modelo

        Args:
            version1: Versión 1 del modelo
            version2: Versión 2 del modelo

        Returns:
            dict: Comparación de métricas
        """
        try:
            from database.models import MLModelMetrics

            session = self.db.get_session()

            # Obtener métricas más recientes de cada versión
            metrics_v1 = session.query(MLModelMetrics)\
                .filter(MLModelMetrics.model_version == version1)\
                .order_by(MLModelMetrics.evaluated_at.desc())\
                .first()

            metrics_v2 = session.query(MLModelMetrics)\
                .filter(MLModelMetrics.model_version == version2)\
                .order_by(MLModelMetrics.evaluated_at.desc())\
                .first()

            session.close()

            if not metrics_v1 or not metrics_v2:
                return {'error': 'Una o ambas versiones no encontradas'}

            # Calcular diferencias
            comparison = {
                'version1': {
                    'version': version1,
                    'accuracy': metrics_v1.accuracy,
                    'precision': metrics_v1.precision,
                    'recall': metrics_v1.recall,
                    'f1_score': metrics_v1.f1_score,
                    'roc_auc': metrics_v1.roc_auc,
                    'evaluated_at': metrics_v1.evaluated_at.isoformat()
                },
                'version2': {
                    'version': version2,
                    'accuracy': metrics_v2.accuracy,
                    'precision': metrics_v2.precision,
                    'recall': metrics_v2.recall,
                    'f1_score': metrics_v2.f1_score,
                    'roc_auc': metrics_v2.roc_auc,
                    'evaluated_at': metrics_v2.evaluated_at.isoformat()
                },
                'differences': {
                    'accuracy': metrics_v2.accuracy - metrics_v1.accuracy,
                    'precision': metrics_v2.precision - metrics_v1.precision,
                    'recall': metrics_v2.recall - metrics_v1.recall,
                    'f1_score': metrics_v2.f1_score - metrics_v1.f1_score,
                    'roc_auc': metrics_v2.roc_auc - metrics_v1.roc_auc
                }
            }

            return comparison

        except Exception as e:
            print(f"[ERROR] Error comparando versiones: {e}")
            return {'error': str(e)}
