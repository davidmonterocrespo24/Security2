#!/usr/bin/env python3
"""
Módulo de Auto-Bloqueo Basado en Machine Learning
Bloquea automáticamente IPs según predicciones ML y políticas configurables
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json


class AutoBlocker:
    """
    Gestiona el bloqueo automático de IPs basado en predicciones ML
    """

    def __init__(self, db_manager, fail2ban_manager=None):
        """
        Inicializar auto-blocker

        Args:
            db_manager: Instancia de DatabaseManager
            fail2ban_manager: Instancia opcional de Fail2banManager
        """
        self.db = db_manager
        self.fail2ban = fail2ban_manager

    def evaluate_ip_for_blocking(self, ip_address: str, ml_prediction: Dict) -> Tuple[bool, str, Dict]:
        """
        Evaluar si una IP debe ser bloqueada según predicción ML y políticas

        Args:
            ip_address: IP a evaluar
            ml_prediction: Diccionario con predicción ML

        Returns:
            Tuple (should_block, reason, metadata)
        """
        # Verificar si ya está bloqueada
        if self._is_already_blocked(ip_address):
            return False, "IP ya bloqueada", {}

        # Verificar si está en whitelist
        if self._is_whitelisted(ip_address):
            return False, "IP en whitelist", {}

        # Obtener política activa
        policy = self._get_active_policy()
        if not policy or not policy.get('enabled', False):
            return False, "Auto-bloqueo deshabilitado", {}

        # Evaluar según política
        ml_confidence = ml_prediction.get('ml_confidence', 0)
        threat_score = ml_prediction.get('threat_score', 0)
        severity = ml_prediction.get('max_severity', 'low')

        # Criterio 1: Confianza ML
        min_confidence = policy.get('min_ml_confidence', 85)
        if ml_confidence < min_confidence:
            return False, f"Confianza ML insuficiente ({ml_confidence}% < {min_confidence}%)", {}

        # Criterio 2: Threat Score
        min_threat_score = policy.get('min_threat_score', 70)
        if threat_score < min_threat_score:
            return False, f"Threat score insuficiente ({threat_score} < {min_threat_score})", {}

        # Criterio 3: Severidad mínima
        min_severity = policy.get('min_severity', 'high')
        severity_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        if severity_levels.get(severity, 0) < severity_levels.get(min_severity, 2):
            return False, f"Severidad insuficiente ({severity} < {min_severity})", {}

        # Criterio 4: Número mínimo de eventos
        min_events = policy.get('min_events', 3)
        event_count = ml_prediction.get('event_count', 0)
        if event_count < min_events:
            return False, f"Eventos insuficientes ({event_count} < {min_events})", {}

        # Criterio 5: Verificar si requiere múltiples fuentes
        require_multiple_sources = policy.get('require_multiple_sources', True)
        if require_multiple_sources:
            sources = set()
            if ml_prediction.get('ml_confidence', 0) > 0:
                sources.add('ml')
            if ml_prediction.get('zeek_detections', 0) > 0:
                sources.add('zeek')
            if ml_prediction.get('f2b_bans', 0) > 0:
                sources.add('fail2ban')

            if len(sources) < 2:
                return False, f"Solo detectado por {len(sources)} fuente(s), se requieren 2+", {}

        # Todos los criterios cumplidos
        reason = (
            f"Auto-bloqueado: ML={ml_confidence:.1f}%, "
            f"ThreatScore={threat_score}, "
            f"Severity={severity}, "
            f"Events={event_count}"
        )

        metadata = {
            'ml_confidence': ml_confidence,
            'threat_score': threat_score,
            'severity': severity,
            'event_count': event_count,
            'policy_id': policy.get('id'),
            'auto_blocked': True
        }

        return True, reason, metadata

    def block_ip(self, ip_address: str, reason: str, metadata: Dict,
                 duration_hours: Optional[int] = None) -> bool:
        """
        Bloquear IP en base de datos y opcionalmente en Fail2ban

        Args:
            ip_address: IP a bloquear
            reason: Razón del bloqueo
            metadata: Metadatos adicionales
            duration_hours: Duración del bloqueo (None = permanente según política)

        Returns:
            True si se bloqueó exitosamente
        """
        try:
            # Obtener política para duración
            policy = self._get_active_policy()
            if duration_hours is None:
                duration_hours = policy.get('default_block_duration', 24)

            # Determinar si es permanente
            is_permanent = policy.get('permanent_block', False)

            # Determinar threat_level según severidad
            severity = metadata.get('severity', 'medium')
            threat_level_map = {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low'
            }
            threat_level = threat_level_map.get(severity, 'medium')

            # Bloquear en base de datos
            success = self.db.block_ip(
                ip_address=ip_address,
                reason=reason,
                blocked_by='auto_blocker',
                jail_name='ml-auto',
                threat_level=threat_level,
                is_permanent=is_permanent
            )

            if not success:
                return False

            # Bloquear en Fail2ban si está disponible
            if self.fail2ban and policy.get('apply_to_fail2ban', True):
                try:
                    self.fail2ban.ban_ip(
                        ip_address,
                        jail_name='ml-auto',
                        duration_hours=duration_hours if not is_permanent else None
                    )
                except Exception as e:
                    print(f"[AutoBlocker] Error bloqueando en Fail2ban: {e}")

            # Crear alerta
            self.db.create_alert(
                alert_type='auto_block',
                severity=severity,
                title=f'IP Auto-Bloqueada: {ip_address}',
                message=reason,
                source='Auto-Blocker ML',
                metadata=metadata
            )

            print(f"[AutoBlocker] IP bloqueada: {ip_address} ({reason})")
            return True

        except Exception as e:
            print(f"[AutoBlocker] Error bloqueando IP {ip_address}: {e}")
            return False

    def process_ml_predictions(self, predictions: List[Dict], dry_run: bool = False) -> Dict:
        """
        Procesar lista de predicciones ML y bloquear según políticas

        Args:
            predictions: Lista de predicciones ML
            dry_run: Si True, solo evalúa sin bloquear

        Returns:
            Diccionario con estadísticas
        """
        stats = {
            'evaluated': 0,
            'blocked': 0,
            'skipped': 0,
            'already_blocked': 0,
            'whitelisted': 0,
            'insufficient_criteria': 0,
            'blocked_ips': [],
            'skipped_ips': []
        }

        for prediction in predictions:
            ip = prediction.get('ip')
            if not ip:
                continue

            stats['evaluated'] += 1

            # Evaluar si debe bloquearse
            should_block, reason, metadata = self.evaluate_ip_for_blocking(ip, prediction)

            if should_block:
                if dry_run:
                    print(f"[DRY-RUN] Bloquearía: {ip} - {reason}")
                    stats['blocked'] += 1
                    stats['blocked_ips'].append({'ip': ip, 'reason': reason})
                else:
                    if self.block_ip(ip, reason, metadata):
                        stats['blocked'] += 1
                        stats['blocked_ips'].append({'ip': ip, 'reason': reason})
                    else:
                        stats['skipped'] += 1
                        stats['skipped_ips'].append({'ip': ip, 'reason': 'Error al bloquear'})
            else:
                stats['skipped'] += 1

                # Clasificar razón del skip
                if 'ya bloqueada' in reason.lower():
                    stats['already_blocked'] += 1
                elif 'whitelist' in reason.lower():
                    stats['whitelisted'] += 1
                else:
                    stats['insufficient_criteria'] += 1

                stats['skipped_ips'].append({'ip': ip, 'reason': reason})

        return stats

    def _is_already_blocked(self, ip_address: str) -> bool:
        """Verificar si IP ya está bloqueada"""
        try:
            blocked_ips = self.db.get_blocked_ips()
            return any(
                b['ip_address'] == ip_address and
                (b.get('is_permanent') or b.get('is_active'))
                for b in blocked_ips
            )
        except:
            return False

    def _is_whitelisted(self, ip_address: str) -> bool:
        """Verificar si IP está en whitelist"""
        try:
            whitelist = self.db.get_whitelist()
            return any(w['ip_address'] == ip_address for w in whitelist)
        except:
            return False

    def _get_active_policy(self) -> Optional[Dict]:
        """Obtener política de auto-bloqueo activa"""
        try:
            policies = self.db.get_auto_block_policies()
            # Buscar primera política activa
            for policy in policies:
                if policy.get('enabled', False):
                    return policy
            return None
        except:
            # Política por defecto si no hay configurada
            return {
                'enabled': False,
                'min_ml_confidence': 85,
                'min_threat_score': 70,
                'min_severity': 'high',
                'min_events': 3,
                'require_multiple_sources': True,
                'default_block_duration': 24,
                'permanent_block': False,
                'apply_to_fail2ban': True
            }

    def get_auto_block_stats(self, hours_back: int = 24) -> Dict:
        """
        Obtener estadísticas de bloqueos automáticos

        Args:
            hours_back: Horas hacia atrás

        Returns:
            Diccionario con estadísticas
        """
        try:
            since = datetime.utcnow() - timedelta(hours=hours_back)

            # Obtener bloqueos automáticos
            all_blocked = self.db.get_blocked_ips()
            auto_blocked = [
                b for b in all_blocked
                if b.get('blocked_by') == 'auto_blocker' and
                datetime.fromisoformat(b['blocked_at']) >= since
            ]

            # Estadísticas por severidad
            by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for block in auto_blocked:
                severity = block.get('threat_level', 'medium')
                by_severity[severity] = by_severity.get(severity, 0) + 1

            return {
                'total_auto_blocked': len(auto_blocked),
                'by_severity': by_severity,
                'currently_active': len([b for b in auto_blocked if b.get('is_active')]),
                'permanent_blocks': len([b for b in auto_blocked if b.get('is_permanent')]),
                'recent_blocks': auto_blocked[:10]  # Últimos 10
            }
        except Exception as e:
            print(f"[AutoBlocker] Error obteniendo estadísticas: {e}")
            return {
                'total_auto_blocked': 0,
                'by_severity': {},
                'currently_active': 0,
                'permanent_blocks': 0,
                'recent_blocks': []
            }


def test_auto_blocker():
    """Función de prueba del auto-blocker"""
    from database.db_manager import DatabaseManager

    print("="*60)
    print("TEST: AUTO-BLOCKER ML")
    print("="*60)

    db = DatabaseManager()
    blocker = AutoBlocker(db)

    # Predicción de prueba
    test_prediction = {
        'ip': '192.168.1.200',
        'ml_confidence': 95.5,
        'threat_score': 85,
        'max_severity': 'high',
        'event_count': 5,
        'zeek_detections': 2,
        'f2b_bans': 1
    }

    print("\n[TEST] Evaluando IP de prueba...")
    print(f"  IP: {test_prediction['ip']}")
    print(f"  ML Confidence: {test_prediction['ml_confidence']}%")
    print(f"  Threat Score: {test_prediction['threat_score']}")
    print(f"  Severity: {test_prediction['max_severity']}")

    should_block, reason, metadata = blocker.evaluate_ip_for_blocking(
        test_prediction['ip'],
        test_prediction
    )

    print(f"\n[RESULTADO]")
    print(f"  Should Block: {should_block}")
    print(f"  Reason: {reason}")

    if should_block:
        print("\n[TEST] Ejecutando bloqueo en modo DRY-RUN...")
        stats = blocker.process_ml_predictions([test_prediction], dry_run=True)
        print(f"  Evaluadas: {stats['evaluated']}")
        print(f"  Bloqueadas: {stats['blocked']}")
        print(f"  Saltadas: {stats['skipped']}")

    print("\n[TEST] Obteniendo estadísticas...")
    stats = blocker.get_auto_block_stats(hours_back=24)
    print(f"  Total auto-bloqueadas (24h): {stats['total_auto_blocked']}")
    print(f"  Actualmente activas: {stats['currently_active']}")

    print("\n" + "="*60)
    print("[OK] Test completado")
    print("="*60)


if __name__ == '__main__':
    test_auto_blocker()
