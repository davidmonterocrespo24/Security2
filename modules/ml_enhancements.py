"""
Mejoras avanzadas para el sistema de Machine Learning
- Análisis conductual de IPs
- Sistema de scoring de amenazas (0-100)
- Explicaciones mejoradas con SHAP
- Características de comportamiento agregado
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import Counter

# SHAP para explicaciones
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


def extract_ip_behavioral_features(ip_address, events_list):
    """
    Extraer características de comportamiento agregado de una IP

    Args:
        ip_address: IP a analizar
        events_list: Lista de eventos de esta IP

    Returns:
        Dict con características conductuales
    """
    if not events_list or len(events_list) == 0:
        return {
            'requests_per_minute': 0,
            'path_diversity_ratio': 0,
            'error_ratio': 0,
            'num_attack_types': 0,
            'temporal_entropy': 0,
            'is_rhythmic_bot': False,
            'escalation_ratio': 1.0,
            'unique_paths': 0,
            'avg_path_length': 0,
            'suspicious_chars_total': 0
        }

    # 1. Velocidad de ataque (requests/minuto)
    if len(events_list) >= 2:
        try:
            first_event = events_list[0].get('timestamp')
            last_event = events_list[-1].get('timestamp')

            # Convertir timestamps
            if isinstance(first_event, str):
                first_event = datetime.fromisoformat(first_event)
            if isinstance(last_event, str):
                last_event = datetime.fromisoformat(last_event)

            time_span = (last_event - first_event).total_seconds() / 60  # minutos
            requests_per_minute = len(events_list) / max(time_span, 1)
        except:
            requests_per_minute = 0
    else:
        requests_per_minute = 0

    # 2. Diversidad de paths
    paths = [e.get('request_path', '/') for e in events_list]
    unique_paths = len(set(paths))
    path_diversity_ratio = unique_paths / len(events_list) if events_list else 0

    # 3. Ratio de errores (eventos de alta severidad)
    error_events = sum(1 for e in events_list if e.get('severity') in ['high', 'critical'])
    error_ratio = error_events / len(events_list) if events_list else 0

    # 4. Tipos de ataque
    attack_vectors = set(e.get('attack_vector') for e in events_list if e.get('attack_vector') and e.get('attack_vector') != 'unknown')
    num_attack_types = len(attack_vectors)

    # 5. Entropía temporal (detección de bots)
    time_intervals = []
    sorted_events = sorted(events_list, key=lambda x: x.get('timestamp', datetime.min))

    for i in range(1, len(sorted_events)):
        try:
            t1 = sorted_events[i-1].get('timestamp')
            t2 = sorted_events[i].get('timestamp')

            if isinstance(t1, str):
                t1 = datetime.fromisoformat(t1)
            if isinstance(t2, str):
                t2 = datetime.fromisoformat(t2)

            interval = (t2 - t1).total_seconds()
            time_intervals.append(interval)
        except:
            continue

    temporal_entropy = np.std(time_intervals) if time_intervals else 0
    is_rhythmic_bot = bool(temporal_entropy < 2 and len(time_intervals) > 3)  # Muy regular = bot

    # 6. Escalamiento (está incrementando?)
    if len(events_list) >= 10:
        first_half = events_list[:len(events_list)//2]
        second_half = events_list[len(events_list)//2:]
        escalation_ratio = len(second_half) / len(first_half) if len(first_half) > 0 else 1.0
    else:
        escalation_ratio = 1.0

    # 7. Longitud promedio de paths
    path_lengths = [len(e.get('request_path', '/')) for e in events_list]
    avg_path_length = float(np.mean(path_lengths)) if path_lengths else 0

    # 8. Total de caracteres sospechosos
    suspicious_chars_total = 0
    for event in events_list:
        path = event.get('request_path', '')
        suspicious_chars_total += sum(1 for c in path if c in ['<', '>', '"', "'", ';', '|', '&', '$', '`'])

    return {
        'requests_per_minute': float(round(requests_per_minute, 2)),
        'path_diversity_ratio': float(round(path_diversity_ratio, 3)),
        'error_ratio': float(round(error_ratio, 3)),
        'num_attack_types': int(num_attack_types),
        'temporal_entropy': float(round(temporal_entropy, 2)),
        'is_rhythmic_bot': is_rhythmic_bot,
        'escalation_ratio': float(round(escalation_ratio, 2)),
        'unique_paths': int(unique_paths),
        'avg_path_length': float(round(avg_path_length, 1)),
        'suspicious_chars_total': int(suspicious_chars_total)
    }


def calculate_threat_score(ip_address, ml_confidence, behavioral_features, country_code='XX'):
    """
    Calcular score de amenaza 0-100 con niveles accionables

    Args:
        ip_address: IP analizada
        ml_confidence: Confianza del modelo ML (0-1)
        behavioral_features: Dict con características conductuales
        country_code: Código ISO del país

    Returns:
        Dict con score, acción recomendada y factores
    """
    score = 0
    factors = []

    # 1. Confianza ML (40 puntos)
    ml_score = ml_confidence * 40
    score += ml_score
    if ml_score > 20:
        factors.append({
            'factor': 'Confianza ML',
            'points': round(ml_score, 1),
            'description': f'{ml_confidence*100:.1f}% confianza de ser malicioso'
        })

    # 2. Velocidad de ataque (20 puntos)
    rpm = behavioral_features.get('requests_per_minute', 0)
    if rpm > 5:  # Más de 5 requests/minuto es sospechoso
        speed_score = min(20, rpm)
        score += speed_score
        factors.append({
            'factor': 'Velocidad de Ataque',
            'points': round(speed_score, 1),
            'description': f'{rpm:.1f} requests/minuto (normal: <2)'
        })

    # 3. Diversidad de ataques (15 puntos)
    num_attack_types = behavioral_features.get('num_attack_types', 0)
    if num_attack_types > 1:
        diversity_score = min(15, num_attack_types * 5)
        score += diversity_score
        factors.append({
            'factor': 'Múltiples Vectores de Ataque',
            'points': round(diversity_score, 1),
            'description': f'{num_attack_types} tipos diferentes de ataque'
        })

    # 4. Ratio de errores (10 puntos)
    error_ratio = behavioral_features.get('error_ratio', 0)
    if error_ratio > 0.3:  # Más del 30% de errores
        error_score = min(10, error_ratio * 10)
        score += error_score
        factors.append({
            'factor': 'Alto Ratio de Errores',
            'points': round(error_score, 1),
            'description': f'{error_ratio*100:.0f}% de requests generan errores críticos'
        })

    # 5. Bot detection (10 puntos)
    if behavioral_features.get('is_rhythmic_bot', False):
        score += 10
        factors.append({
            'factor': 'Patrón de Bot Automatizado',
            'points': 10,
            'description': 'Intervalos regulares detectados (no humano)'
        })

    # 6. País de riesgo (5 puntos)
    high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'BY', 'VN']
    if country_code in high_risk_countries:
        score += 5
        factors.append({
            'factor': 'País de Alto Riesgo',
            'points': 5,
            'description': f'Origen: {country_code}'
        })

    # 7. Escalamiento (5 puntos bonus)
    escalation = behavioral_features.get('escalation_ratio', 1.0)
    if escalation > 2:
        score += 5
        factors.append({
            'factor': 'Escalamiento de Ataque',
            'points': 5,
            'description': f'Actividad incrementó {escalation:.1f}x en última mitad del período'
        })

    # 8. Caracteres sospechosos (5 puntos)
    suspicious_chars = behavioral_features.get('suspicious_chars_total', 0)
    if suspicious_chars > 10:
        susp_score = min(5, suspicious_chars / 10)
        score += susp_score
        factors.append({
            'factor': 'Caracteres Maliciosos',
            'points': round(susp_score, 1),
            'description': f'{suspicious_chars} caracteres sospechosos en URLs'
        })

    # 9. Paths muy largos (5 puntos)
    avg_path_length = behavioral_features.get('avg_path_length', 0)
    if avg_path_length > 150:
        path_score = min(5, (avg_path_length - 150) / 50)
        score += path_score
        factors.append({
            'factor': 'URLs Anormalmente Largas',
            'points': round(path_score, 1),
            'description': f'Promedio de {avg_path_length:.0f} caracteres (normal: <100)'
        })

    # Determinar acción recomendada basada en score
    if score >= 80:
        action = 'BLOCK_IMMEDIATE'
        action_text = '🚫 BLOQUEAR INMEDIATAMENTE'
        action_description = 'Amenaza crítica confirmada - Acción inmediata requerida'
        color = 'red'
        priority = 'critical'
    elif score >= 60:
        action = 'BLOCK_DELAYED'
        action_text = '⏸️ BLOQUEAR (24h gracia)'
        action_description = 'Alta probabilidad de amenaza - Bloqueo recomendado'
        color = 'orange'
        priority = 'high'
    elif score >= 40:
        action = 'THROTTLE'
        action_text = '⚠️ LIMITAR TASA'
        action_description = 'Comportamiento sospechoso - Aplicar rate limiting'
        color = 'yellow'
        priority = 'medium'
    elif score >= 20:
        action = 'MONITOR'
        action_text = '👁️ MONITOREAR'
        action_description = 'Actividad anómala detectada - Monitoreo cercano'
        color = 'blue'
        priority = 'low'
    else:
        action = 'ALLOW'
        action_text = '✅ PERMITIR'
        action_description = 'Riesgo bajo - No se requiere acción'
        color = 'green'
        priority = 'info'

    return {
        'threat_score': min(100, round(score, 1)),
        'action': action,
        'action_text': action_text,
        'action_description': action_description,
        'color': color,
        'priority': priority,
        'factors': factors,
        'factors_count': len(factors)
    }


def generate_enhanced_reason(features_df, prediction, confidence, behavioral_features, threat_score_info):
    """
    Generar explicación detallada con análisis conductual

    Args:
        features_df: DataFrame con características del evento
        prediction: Predicción del modelo (0 o 1)
        confidence: Confianza de la predicción
        behavioral_features: Dict con características conductuales
        threat_score_info: Info del threat scoring

    Returns:
        String con explicación detallada
    """
    reasons = []

    # 1. Clasificación principal
    if prediction == 1:
        reasons.append(f"⚠️ **CLASIFICADO COMO MALICIOSO** ({confidence*100:.1f}% confianza)")
    else:
        reasons.append(f"✅ **CLASIFICADO COMO NORMAL** ({(1-confidence)*100:.1f}% confianza)")

    # 2. Threat Score
    score = threat_score_info['threat_score']
    action = threat_score_info['action_text']
    reasons.append(f"\n**Threat Score: {score}/100** - {action}")

    # 3. Análisis Conductual
    if behavioral_features:
        reasons.append("\n**📊 Análisis de Comportamiento:**")

        rpm = behavioral_features.get('requests_per_minute', 0)
        if rpm > 2:
            reasons.append(f"  • {rpm:.1f} requests/minuto (anormal, promedio normal: ~0.5)")

        attack_types = behavioral_features.get('num_attack_types', 0)
        if attack_types > 0:
            reasons.append(f"  • {attack_types} vectores de ataque diferentes detectados")

        error_ratio = behavioral_features.get('error_ratio', 0)
        if error_ratio > 0.3:
            reasons.append(f"  • {error_ratio*100:.0f}% de requests resultaron en errores críticos")

        if behavioral_features.get('is_rhythmic_bot'):
            reasons.append(f"  • Patrón bot detectado (intervalos regulares de ~{behavioral_features.get('temporal_entropy', 0):.1f}s)")

        escalation = behavioral_features.get('escalation_ratio', 1.0)
        if escalation > 2:
            reasons.append(f"  • Escalamiento: {escalation:.1f}x más actividad en última hora")

    # 4. Factores del Threat Score
    if threat_score_info.get('factors'):
        reasons.append(f"\n**🔍 Factores Principales ({threat_score_info['factors_count']} detectados):**")
        for factor in threat_score_info['factors'][:5]:  # Top 5
            reasons.append(f"  • **{factor['factor']}** (+{factor['points']} pts): {factor['description']}")

    # 5. Características específicas del evento
    if features_df is not None and len(features_df) > 0:
        row = features_df.iloc[0]

        event_reasons = []

        if row.get('severity_level', 0) >= 3:
            sev_map = {1: 'baja', 2: 'media', 3: 'alta', 4: 'crítica'}
            event_reasons.append(f"Severidad {sev_map.get(row['severity_level'], 'desconocida')}")

        if row.get('suspicious_chars', 0) > 3:
            event_reasons.append(f"{int(row['suspicious_chars'])} caracteres maliciosos en URL")

        if row.get('path_length', 0) > 100:
            event_reasons.append(f"URL muy larga ({int(row['path_length'])} chars)")

        if row.get('is_night', 0) == 1:
            hour = row.get('hour', 0)
            event_reasons.append(f"Horario sospechoso ({int(hour)}:00 hrs)")

        if event_reasons:
            reasons.append("\n**🎯 Características del Evento:**")
            for reason in event_reasons:
                reasons.append(f"  • {reason}")

    # 6. Recomendación
    reasons.append(f"\n**{threat_score_info['action_text']}**")
    reasons.append(f"   {threat_score_info['action_description']}")

    return "\n".join(reasons)


def get_feature_importance_explanation(model, feature_names, features_df, top_n=5):
    """
    Obtener explicación basada en feature importance del modelo

    Args:
        model: Modelo entrenado
        feature_names: Lista de nombres de features
        features_df: DataFrame con las características
        top_n: Top N características a mostrar

    Returns:
        Dict con explicación de feature importance
    """
    if model is None or not hasattr(model, 'feature_importances_'):
        return None

    # Obtener feature importances
    importances = model.feature_importances_

    # Crear DataFrame
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    }).sort_values('importance', ascending=False)

    # Obtener valores actuales de las features
    row = features_df.iloc[0]

    # Top N features
    top_features = []
    for idx, feat_row in importance_df.head(top_n).iterrows():
        feature = feat_row['feature']
        importance = feat_row['importance']

        # Obtener valor actual si existe
        value = row.get(feature, 'N/A')

        top_features.append({
            'feature': feature,
            'importance': round(importance * 100, 1),
            'value': value,
            'description': _get_feature_description(feature, value)
        })

    return {
        'top_features': top_features,
        'total_features': len(feature_names)
    }


def _get_feature_description(feature_name, value):
    """Traducir nombre de feature a descripción legible"""
    descriptions = {
        'severity_level': f'Nivel de severidad: {value}',
        'suspicious_chars': f'{value} caracteres sospechosos',
        'path_length': f'Longitud de URL: {value} caracteres',
        'hour': f'Hora del día: {value}:00',
        'is_night': 'Horario nocturno' if value == 1 else 'Horario diurno',
        'is_weekend': 'Fin de semana' if value == 1 else 'Día laborable',
        'ua_length': f'User-Agent: {value} caracteres',
        'is_bot': 'Bot detectado' if value == 1 else 'No es bot',
        'has_query_string': 'Tiene query string' if value == 1 else 'Sin query string'
    }

    return descriptions.get(feature_name, f'{feature_name}: {value}')
