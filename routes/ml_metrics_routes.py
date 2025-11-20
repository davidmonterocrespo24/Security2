"""
API Routes - ML Model Metrics
Endpoints para métricas y evaluación del modelo de Machine Learning
"""

from flask import Blueprint, jsonify, request, render_template
import traceback


def create_ml_metrics_blueprint(ml_metrics):
    """
    Crear Blueprint para rutas de métricas ML

    Args:
        ml_metrics: Instancia de MLMetrics
    """
    ml_metrics_bp = Blueprint('ml_metrics', __name__, url_prefix='/ml-metrics')

    # ========================================================================
    # EVALUACIÓN DEL MODELO
    # ========================================================================

    @ml_metrics_bp.route('/api/evaluate', methods=['POST'])
    def evaluate_model():
        """
        POST /ml-metrics/api/evaluate
        Evaluar el modelo ML y calcular métricas

        Response:
            {
                "success": true,
                "metrics": {
                    "accuracy": 0.95,
                    "precision": 0.93,
                    "recall": 0.94,
                    "f1_score": 0.935,
                    "roc_auc": 0.96,
                    "confusion_matrix": [[tn, fp], [fn, tp]],
                    "samples_evaluated": 1000,
                    ...
                },
                "metric_id": 123
            }
        """
        try:
            print("\n[API] Solicitud de evaluación del modelo recibida")

            # Evaluar modelo
            metrics = ml_metrics.evaluate_model()

            if 'error' in metrics:
                return jsonify({
                    'success': False,
                    'error': metrics['error']
                }), 400

            # Guardar métricas en BD
            metric_id = ml_metrics.save_metrics(metrics)

            return jsonify({
                'success': True,
                'metrics': metrics,
                'metric_id': metric_id,
                'message': 'Modelo evaluado exitosamente'
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # MÉTRICAS ACTUALES
    # ========================================================================

    @ml_metrics_bp.route('/api/current', methods=['GET'])
    def get_current_metrics():
        """
        GET /ml-metrics/api/current
        Obtener las métricas más recientes del modelo

        Response:
            {
                "success": true,
                "metrics": {
                    "id": 5,
                    "model_version": "v1.2.0",
                    "evaluated_at": "2025-11-20T...",
                    "accuracy": 0.95,
                    ...
                }
            }
        """
        try:
            # Obtener última evaluación
            history = ml_metrics.get_metrics_history(days_back=365, limit=1)

            if not history:
                return jsonify({
                    'success': True,
                    'metrics': None,
                    'message': 'No hay métricas disponibles. Evalúe el modelo primero.'
                })

            return jsonify({
                'success': True,
                'metrics': history[0]
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # HISTÓRICO DE MÉTRICAS
    # ========================================================================

    @ml_metrics_bp.route('/api/history', methods=['GET'])
    def get_metrics_history():
        """
        GET /ml-metrics/api/history
        Obtener histórico de métricas

        Query params:
            - days: Días hacia atrás (default: 30)
            - limit: Límite de registros (default: 50)

        Response:
            {
                "success": true,
                "history": [
                    {
                        "id": 5,
                        "model_version": "v1.2.0",
                        "evaluated_at": "2025-11-20T...",
                        "accuracy": 0.95,
                        ...
                    }
                ],
                "total": 10
            }
        """
        try:
            days = int(request.args.get('days', 30))
            limit = int(request.args.get('limit', 50))

            history = ml_metrics.get_metrics_history(days_back=days, limit=limit)

            return jsonify({
                'success': True,
                'history': history,
                'total': len(history),
                'days_back': days
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # COMPARACIÓN DE VERSIONES
    # ========================================================================

    @ml_metrics_bp.route('/api/compare', methods=['GET'])
    def compare_versions():
        """
        GET /ml-metrics/api/compare
        Comparar métricas entre dos versiones del modelo

        Query params:
            - version1: Primera versión
            - version2: Segunda versión

        Response:
            {
                "success": true,
                "comparison": {
                    "version1": {...},
                    "version2": {...},
                    "differences": {
                        "accuracy": 0.02,
                        "precision": -0.01,
                        ...
                    }
                }
            }
        """
        try:
            version1 = request.args.get('version1')
            version2 = request.args.get('version2')

            if not version1 or not version2:
                return jsonify({
                    'success': False,
                    'error': 'Se requieren version1 y version2'
                }), 400

            comparison = ml_metrics.compare_versions(version1, version2)

            if 'error' in comparison:
                return jsonify({
                    'success': False,
                    'error': comparison['error']
                }), 404

            return jsonify({
                'success': True,
                'comparison': comparison
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # FEATURE IMPORTANCE
    # ========================================================================

    @ml_metrics_bp.route('/api/feature-importance', methods=['GET'])
    def get_feature_importance():
        """
        GET /ml-metrics/api/feature-importance
        Obtener importancia de características del modelo

        Query params:
            - top_n: Número de features a retornar (default: 20)

        Response:
            {
                "success": true,
                "features": ["hour", "severity_level", ...],
                "importances": [0.25, 0.18, ...],
                "total_features": 35
            }
        """
        try:
            top_n = int(request.args.get('top_n', 20))

            importance = ml_metrics.get_feature_importance(top_n=top_n)

            if 'error' in importance:
                return jsonify({
                    'success': False,
                    'error': importance['error']
                }), 400

            return jsonify({
                'success': True,
                **importance
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # DETALLES DE MÉTRICA ESPECÍFICA
    # ========================================================================

    @ml_metrics_bp.route('/api/metrics/<int:metric_id>', methods=['GET'])
    def get_metric_details(metric_id):
        """
        GET /ml-metrics/api/metrics/<id>
        Obtener detalles completos de una métrica específica

        Response:
            {
                "success": true,
                "metric": {
                    "id": 5,
                    "model_version": "v1.2.0",
                    "confusion_matrix": [[100, 5], [3, 92]],
                    "roc_curve_data": {...},
                    "pr_curve_data": {...},
                    ...
                }
            }
        """
        try:
            from database.models import MLModelMetrics

            session = ml_metrics.db.get_session()

            metric = session.query(MLModelMetrics)\
                .filter(MLModelMetrics.id == metric_id)\
                .first()

            session.close()

            if not metric:
                return jsonify({
                    'success': False,
                    'error': f'Métrica {metric_id} no encontrada'
                }), 404

            return jsonify({
                'success': True,
                'metric': metric.to_dict()
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # ESTADÍSTICAS RESUMIDAS
    # ========================================================================

    @ml_metrics_bp.route('/api/summary', methods=['GET'])
    def get_summary():
        """
        GET /ml-metrics/api/summary
        Obtener resumen de métricas del modelo

        Response:
            {
                "success": true,
                "summary": {
                    "latest_metrics": {...},
                    "total_evaluations": 15,
                    "average_accuracy": 0.94,
                    "trend": "improving",
                    "last_evaluated": "2025-11-20T..."
                }
            }
        """
        try:
            # Obtener últimas métricas
            history = ml_metrics.get_metrics_history(days_back=365, limit=100)

            if not history:
                return jsonify({
                    'success': True,
                    'summary': {
                        'latest_metrics': None,
                        'total_evaluations': 0,
                        'message': 'No hay datos disponibles'
                    }
                })

            # Calcular promedios
            avg_accuracy = sum(h['accuracy'] for h in history) / len(history)
            avg_precision = sum(h['precision'] for h in history) / len(history)
            avg_recall = sum(h['recall'] for h in history) / len(history)
            avg_f1 = sum(h['f1_score'] for h in history) / len(history)

            # Determinar tendencia (comparar últimas 2 evaluaciones)
            trend = 'stable'
            if len(history) >= 2:
                recent_acc = history[0]['accuracy']
                prev_acc = history[1]['accuracy']
                if recent_acc > prev_acc + 0.01:
                    trend = 'improving'
                elif recent_acc < prev_acc - 0.01:
                    trend = 'degrading'

            summary = {
                'latest_metrics': history[0],
                'total_evaluations': len(history),
                'averages': {
                    'accuracy': avg_accuracy,
                    'precision': avg_precision,
                    'recall': avg_recall,
                    'f1_score': avg_f1
                },
                'trend': trend,
                'last_evaluated': history[0]['evaluated_at']
            }

            return jsonify({
                'success': True,
                'summary': summary
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # ========================================================================
    # DASHBOARD WEB
    # ========================================================================

    @ml_metrics_bp.route('/', methods=['GET'])
    @ml_metrics_bp.route('/dashboard', methods=['GET'])
    def dashboard():
        """
        GET /ml-metrics/dashboard
        Dashboard de métricas del modelo ML
        """
        return render_template('ml_metrics_dashboard.html')

    return ml_metrics_bp
