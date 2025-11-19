#!/bin/bash

echo "=========================================="
echo "TEST: INTEGRACIÓN ZEEK + MACHINE LEARNING"
echo "=========================================="
echo ""

cd /home/Security2
source .venv/bin/activate

echo "PASO 1: Crear eventos automáticos desde detecciones de Zeek"
echo "-----------------------------------------------------------"
python3 << 'EOF'
import sys
sys.path.insert(0, '.')

from modules.zeek_ml_integration import zeek_auto_detect_and_create_events

print("\n🔍 Analizando datos de Zeek para crear eventos de seguridad...")
result = zeek_auto_detect_and_create_events(hours_back=24)

print(f"\n✅ RESULTADO:")
print(f"  Eventos creados: {result['records_created']}")
print(f"  - Port scans: {result['port_scans']}")
print(f"  - DNS tunneling: {result['dns_tunneling']}")
print(f"  - DGA domains: {result['dga_domains']}")
print(f"  - Beaconing (C&C): {result['beaconing']}")
print(f"  - SSL issues: {result['ssl_issues']}")
EOF

echo ""
echo ""
echo "PASO 2: Re-entrenar modelo ML con datos enriquecidos de Zeek"
echo "------------------------------------------------------------"
python3 << 'EOF'
import sys
sys.path.insert(0, '.')

from database.db_manager import DatabaseManager
from modules.ml_detector import MLTrafficDetector

print("\n🤖 Iniciando entrenamiento del modelo ML...")
print("  (Ahora incluye 18 características de Zeek por IP)")
print("")

db = DatabaseManager()
ml = MLTrafficDetector(db)

result = ml.train_model()

if result['success']:
    print(f"\n✅ MODELO ENTRENADO EXITOSAMENTE")
    print(f"  Accuracy: {result['accuracy']*100:.2f}%")
    print(f"  Muestras de entrenamiento: {result['training_samples']}")
    print(f"  Muestras de prueba: {result['test_samples']}")
    print(f"  Ratio malicioso: {result['malicious_ratio']*100:.1f}%")
    print("")
    print(f"Top 5 características más importantes:")
    for i, feat in enumerate(result['feature_importance'][:5], 1):
        print(f"  {i}. {feat['feature']}: {feat['importance']:.4f}")
else:
    print(f"\n❌ ERROR: {result.get('error')}")
EOF

echo ""
echo ""
echo "PASO 3: Probar predicción ML con datos de Zeek"
echo "----------------------------------------------"
python3 << 'EOF'
import sys
sys.path.insert(0, '.')

from database.db_manager import DatabaseManager
from modules.ml_detector import MLTrafficDetector

db = DatabaseManager()
ml = MLTrafficDetector(db)

print("\n🎯 Analizando IPs sospechosas con ML + Zeek...")
print("")

suspicious_ips = ml.get_suspicious_ips(hours_back=24, min_confidence=0.5)

if suspicious_ips:
    print(f"\n📊 RESULTADO: {len(suspicious_ips)} IPs sospechosas detectadas")
    print("")
    print(f"Top 5 IPs más peligrosas:")
    print(f"{'='*80}")

    for i, ip_info in enumerate(suspicious_ips[:5], 1):
        print(f"\n{i}. IP: {ip_info['ip_address']}")
        print(f"   Threat Score: {ip_info['threat_score']}/100 ({ip_info['action_text']})")
        print(f"   ML Confidence: {ip_info['ml_confidence']*100:.1f}%")
        print(f"   Eventos: {ip_info['total_events']} | Maliciosos: {ip_info['suspicious_events']}")

        # Mostrar características de Zeek si están disponibles
        bf = ip_info.get('behavioral_features', {})
        if bf:
            print(f"   Requests/min: {bf.get('requests_per_minute', 0):.1f} | Error ratio: {bf.get('error_ratio', 0):.1%}")

        # Mostrar razones
        reasons = ip_info.get('reasons', '')
        if reasons:
            print(f"   Razones: {reasons[:150]}...")
else:
    print("\n✅ No se detectaron IPs sospechosas en las últimas 24 horas")

EOF

echo ""
echo ""
echo "=========================================="
echo "TEST COMPLETADO"
echo "=========================================="
echo ""
echo "El modelo ML ahora está usando datos de Zeek para:"
echo "  ✅ Detectar port scans automáticamente"
echo "  ✅ Identificar DNS tunneling"
echo "  ✅ Detectar beaconing (C&C)"
echo "  ✅ Analizar certificados SSL"
echo "  ✅ Evaluar patrones de comportamiento de red"
echo ""
echo "Próximo paso: Configurar tareas programadas para ejecutar esto cada 5 minutos"
echo ""
