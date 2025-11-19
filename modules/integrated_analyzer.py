"""
Modulo de Analisis Integrado - Combina datos de ML, Zeek y Fail2ban
"""

from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy import func, desc, and_


class IntegratedAnalyzer:
    """
    Analizador que combina datos de multiples fuentes para obtener
    una vista unificada de amenazas
    """

    def __init__(self, db_manager):
        """
        Inicializar analizador integrado

        Args:
            db_manager: Instancia de DatabaseManager
        """
        self.db = db_manager

    def get_top_threats(self, hours_back=24, limit=10):
        """
        Obtener las IPs mas peligrosas combinando ML + Zeek + Fail2ban

        Score calculado como:
        - ML confidence (0-100 puntos)
        - Zeek detections * 10 puntos
        - Fail2ban bans * 20 puntos
        - Event severity: CRITICAL=50, HIGH=30, MEDIUM=10, LOW=5

        Args:
            hours_back: Horas hacia atras a analizar
            limit: Numero maximo de IPs a retornar

        Returns:
            list: Lista de dicts con IPs y sus scores
        """
        from database.models import SecurityEvent, MLPrediction

        session = self.db.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            # Obtener todas las IPs con eventos
            events = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= cutoff
            ).all()

            # Calcular scores por IP
            ip_scores = defaultdict(lambda: {
                'ip': '',
                'score': 0,
                'ml_confidence': 0,
                'ml_count': 0,
                'zeek_detections': 0,
                'fail2ban_bans': 0,
                'total_events': 0,
                'severities': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'country': 'Unknown',
                'last_seen': None,
                'event_types': []
            })

            severity_scores = {
                'critical': 50,
                'high': 30,
                'medium': 10,
                'low': 5
            }

            for event in events:
                ip = event.source_ip
                if not ip or ip == 'unknown':
                    continue

                data = ip_scores[ip]
                data['ip'] = ip
                data['total_events'] += 1

                # Actualizar ultima vez visto
                if not data['last_seen'] or event.timestamp > data['last_seen']:
                    data['last_seen'] = event.timestamp

                # Obtener pais si esta disponible
                if hasattr(event, 'country') and event.country:
                    data['country'] = event.country

                # Calcular score por tipo de evento
                event_type = event.event_type.lower()

                # ML predictions
                if 'ml_' in event_type or event_type == 'suspicious_traffic':
                    data['ml_count'] += 1
                    # Buscar confianza ML
                    ml_pred = session.query(MLPrediction).filter(
                        MLPrediction.source_ip == ip,
                        MLPrediction.predicted_at >= cutoff
                    ).order_by(MLPrediction.confidence.desc()).first()

                    if ml_pred:
                        confidence = int(ml_pred.confidence * 100)
                        if confidence > data['ml_confidence']:
                            data['ml_confidence'] = confidence
                            data['score'] += confidence

                # Zeek detections
                elif any(x in event_type for x in ['port_scan', 'dns_tunnel', 'beaconing', 'dga', 'ssl']):
                    data['zeek_detections'] += 1
                    data['score'] += 10

                # Fail2ban bans
                elif 'ban' in event_type or 'blocked' in event_type:
                    data['fail2ban_bans'] += 1
                    data['score'] += 20

                # Score por severidad
                severity = event.severity.lower()
                if severity in severity_scores:
                    data['score'] += severity_scores[severity]
                    data['severities'][severity.upper()] += 1

                # Agregar tipo de evento
                if event_type not in data['event_types']:
                    data['event_types'].append(event_type)

            # Convertir a lista y ordenar por score
            threats = list(ip_scores.values())
            threats.sort(key=lambda x: x['score'], reverse=True)

            # Formatear fechas
            for threat in threats[:limit]:
                if threat['last_seen']:
                    threat['last_seen'] = threat['last_seen'].isoformat()

            return threats[:limit]

        except Exception as e:
            print(f"Error en get_top_threats: {e}")
            return []
        finally:
            session.close()

    def get_threat_map(self, hours_back=24):
        """
        Obtener mapa de amenazas por pais

        Args:
            hours_back: Horas hacia atras

        Returns:
            dict: {'CN': {'count': 45, 'avg_score': 75, 'ips': ['1.2.3.4']}, ...}
        """
        from database.models import SecurityEvent

        session = self.db.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            # Obtener eventos con pais
            events = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= cutoff
            ).all()

            country_data = defaultdict(lambda: {
                'count': 0,
                'total_score': 0,
                'avg_score': 0,
                'ips': set(),
                'events': {'ml': 0, 'zeek': 0, 'fail2ban': 0}
            })

            severity_scores = {'critical': 50, 'high': 30, 'medium': 10, 'low': 5}

            for event in events:
                country = getattr(event, 'country', None) or 'Unknown'
                if not country or country == 'Unknown':
                    continue

                data = country_data[country]
                data['count'] += 1

                # Agregar IP unica
                if event.source_ip:
                    data['ips'].add(event.source_ip)

                # Calcular score
                score = severity_scores.get(event.severity.lower(), 5)
                data['total_score'] += score

                # Contar por tipo
                event_type = event.event_type.lower()
                if 'ml_' in event_type or event_type == 'suspicious_traffic':
                    data['events']['ml'] += 1
                elif any(x in event_type for x in ['port_scan', 'dns_tunnel', 'beaconing', 'dga', 'ssl']):
                    data['events']['zeek'] += 1
                elif 'ban' in event_type or 'blocked' in event_type:
                    data['events']['fail2ban'] += 1

            # Calcular promedios y convertir sets a listas
            result = {}
            for country, data in country_data.items():
                result[country] = {
                    'count': data['count'],
                    'avg_score': round(data['total_score'] / data['count'], 2) if data['count'] > 0 else 0,
                    'unique_ips': len(data['ips']),
                    'ips': list(data['ips'])[:10],  # Solo primeras 10 IPs
                    'events': data['events']
                }

            return result

        except Exception as e:
            print(f"Error en get_threat_map: {e}")
            return {}
        finally:
            session.close()

    def get_attack_timeline(self, hours_back=24, interval_minutes=60):
        """
        Obtener timeline de ataques agrupados por intervalo

        Args:
            hours_back: Horas hacia atras
            interval_minutes: Intervalo de agrupacion en minutos

        Returns:
            list: [{'timestamp': '2025-11-19 14:00', 'ml': 5, 'zeek': 12, 'fail2ban': 3}, ...]
        """
        from database.models import SecurityEvent

        session = self.db.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            events = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= cutoff
            ).order_by(SecurityEvent.timestamp).all()

            # Agrupar por intervalos
            timeline = defaultdict(lambda: {
                'timestamp': None,
                'ml_detections': 0,
                'zeek_detections': 0,
                'fail2ban_bans': 0,
                'total': 0,
                'severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            })

            for event in events:
                # Redondear timestamp al intervalo
                minutes = (event.timestamp.hour * 60 + event.timestamp.minute)
                interval_start = (minutes // interval_minutes) * interval_minutes
                hour = interval_start // 60
                minute = interval_start % 60

                bucket_time = event.timestamp.replace(hour=hour, minute=minute, second=0, microsecond=0)
                bucket_key = bucket_time.strftime('%Y-%m-%d %H:%M')

                data = timeline[bucket_key]
                data['timestamp'] = bucket_key
                data['total'] += 1

                # Clasificar por tipo
                event_type = event.event_type.lower()
                if 'ml_' in event_type or event_type == 'suspicious_traffic':
                    data['ml_detections'] += 1
                elif any(x in event_type for x in ['port_scan', 'dns_tunnel', 'beaconing', 'dga', 'ssl']):
                    data['zeek_detections'] += 1
                elif 'ban' in event_type or 'blocked' in event_type:
                    data['fail2ban_bans'] += 1

                # Contar severidad
                severity = event.severity.upper()
                if severity in data['severity']:
                    data['severity'][severity] += 1

            # Convertir a lista ordenada
            result = sorted(timeline.values(), key=lambda x: x['timestamp'])

            return result

        except Exception as e:
            print(f"Error en get_attack_timeline: {e}")
            return []
        finally:
            session.close()

    def get_correlation_stats(self, hours_back=24):
        """
        Obtener estadisticas de correlacion entre sistemas

        Returns:
            dict: Estadisticas de como se relacionan ML, Zeek y Fail2ban
        """
        from database.models import SecurityEvent

        session = self.db.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            events = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= cutoff
            ).all()

            # IPs detectadas por cada sistema
            ml_ips = set()
            zeek_ips = set()
            fail2ban_ips = set()

            for event in events:
                ip = event.source_ip
                if not ip or ip == 'unknown':
                    continue

                event_type = event.event_type.lower()

                if 'ml_' in event_type or event_type == 'suspicious_traffic':
                    ml_ips.add(ip)
                elif any(x in event_type for x in ['port_scan', 'dns_tunnel', 'beaconing', 'dga', 'ssl']):
                    zeek_ips.add(ip)
                elif 'ban' in event_type or 'blocked' in event_type:
                    fail2ban_ips.add(ip)

            # Calcular intersecciones
            ml_and_zeek = ml_ips & zeek_ips
            ml_and_fail2ban = ml_ips & fail2ban_ips
            zeek_and_fail2ban = zeek_ips & fail2ban_ips
            all_three = ml_ips & zeek_ips & fail2ban_ips

            return {
                'ml_unique': len(ml_ips),
                'zeek_unique': len(zeek_ips),
                'fail2ban_unique': len(fail2ban_ips),
                'ml_and_zeek': len(ml_and_zeek),
                'ml_and_fail2ban': len(ml_and_fail2ban),
                'zeek_and_fail2ban': len(zeek_and_fail2ban),
                'all_three': len(all_three),
                'ml_and_zeek_ips': list(ml_and_zeek)[:10],
                'all_three_ips': list(all_three)[:10]
            }

        except Exception as e:
            print(f"Error en get_correlation_stats: {e}")
            return {}
        finally:
            session.close()

    def get_dashboard_summary(self, hours_back=24):
        """
        Obtener resumen completo para dashboard

        Args:
            hours_back: Horas hacia atras

        Returns:
            dict: Resumen con todas las metricas principales
        """
        from database.models import SecurityEvent

        session = self.db.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)

            # Contar eventos totales
            total_events = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= cutoff
            ).count()

            # Contar por severidad
            severities = session.query(
                SecurityEvent.severity,
                func.count(SecurityEvent.id)
            ).filter(
                SecurityEvent.timestamp >= cutoff
            ).group_by(SecurityEvent.severity).all()

            severity_counts = {s[0].upper(): s[1] for s in severities}

            # Contar por tipo
            ml_count = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.event_type.like('%ml_%')
            ).count()

            zeek_count = session.query(SecurityEvent).filter(
                and_(
                    SecurityEvent.timestamp >= cutoff,
                    SecurityEvent.event_type.in_(['port_scan', 'dns_tunneling', 'beaconing', 'dga_domain', 'ssl_self_signed'])
                )
            ).count()

            fail2ban_count = session.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.event_type.like('%ban%')
            ).count()

            # Contar IPs unicas
            unique_ips = session.query(
                func.count(func.distinct(SecurityEvent.source_ip))
            ).filter(
                SecurityEvent.timestamp >= cutoff
            ).scalar()

            # Contar paises unicos
            unique_countries = session.query(
                func.count(func.distinct(SecurityEvent.country))
            ).filter(
                SecurityEvent.timestamp >= cutoff
            ).scalar()

            return {
                'total_events': total_events,
                'unique_ips': unique_ips,
                'unique_countries': unique_countries,
                'severity_counts': severity_counts,
                'by_source': {
                    'ml': ml_count,
                    'zeek': zeek_count,
                    'fail2ban': fail2ban_count
                },
                'hours_back': hours_back
            }

        except Exception as e:
            print(f"Error en get_dashboard_summary: {e}")
            return {}
        finally:
            session.close()

    def get_ip_details(self, ip):
        """
        Obtener detalles completos de una IP especifica

        Args:
            ip: Direccion IP a analizar

        Returns:
            dict: Informacion completa de la IP
        """
        from database.models import SecurityEvent, MLPrediction, IPGeolocation

        session = self.db.get_session()
        try:
            # Eventos de la IP
            events = session.query(SecurityEvent).filter(
                SecurityEvent.source_ip == ip
            ).order_by(SecurityEvent.timestamp.desc()).limit(50).all()

            # Predicciones ML
            ml_predictions = session.query(MLPrediction).filter(
                MLPrediction.source_ip == ip
            ).order_by(MLPrediction.predicted_at.desc()).limit(10).all()

            # Geolocalizacion
            geo = session.query(IPGeolocation).filter(
                IPGeolocation.ip == ip
            ).first()

            # Calcular estadisticas
            event_types = defaultdict(int)
            severities = defaultdict(int)
            first_seen = None
            last_seen = None

            for event in events:
                event_types[event.event_type] += 1
                severities[event.severity.upper()] += 1

                if not first_seen or event.timestamp < first_seen:
                    first_seen = event.timestamp
                if not last_seen or event.timestamp > last_seen:
                    last_seen = event.timestamp

            # ML stats
            ml_stats = {
                'total_predictions': len(ml_predictions),
                'avg_confidence': 0,
                'max_confidence': 0
            }

            if ml_predictions:
                confidences = [p.confidence for p in ml_predictions]
                ml_stats['avg_confidence'] = round(sum(confidences) / len(confidences), 4)
                ml_stats['max_confidence'] = round(max(confidences), 4)

            return {
                'ip': ip,
                'total_events': len(events),
                'event_types': dict(event_types),
                'severities': dict(severities),
                'first_seen': first_seen.isoformat() if first_seen else None,
                'last_seen': last_seen.isoformat() if last_seen else None,
                'ml_stats': ml_stats,
                'geolocation': {
                    'country': geo.country if geo else 'Unknown',
                    'country_code': geo.country_code if geo else 'XX',
                    'city': geo.city if geo else 'Unknown',
                    'latitude': geo.latitude if geo else 0,
                    'longitude': geo.longitude if geo else 0
                } if geo else None,
                'recent_events': [
                    {
                        'type': e.event_type,
                        'severity': e.severity,
                        'timestamp': e.timestamp.isoformat(),
                        'details': e.details
                    }
                    for e in events[:10]
                ]
            }

        except Exception as e:
            print(f"Error en get_ip_details: {e}")
            return {}
        finally:
            session.close()
