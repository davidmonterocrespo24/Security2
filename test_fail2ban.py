#!/usr/bin/env python3
"""
Script de prueba para verificar que Fail2ban bloquea IPs correctamente
Uso: python3 test_fail2ban.py http://tu-servidor.com
"""

import requests
import time
import sys
import argparse
from datetime import datetime

def test_fail2ban(url, num_requests=150, delay=0.05):
    """
    Hace múltiples peticiones HTTP para probar el bloqueo de Fail2ban

    Args:
        url: URL del servidor a probar
        num_requests: Número de peticiones a hacer
        delay: Pausa entre peticiones (segundos)
    """
    print("=" * 60)
    print("Test de Fail2ban - Bloqueo de IPs")
    print("=" * 60)
    print(f"URL: {url}")
    print(f"Peticiones: {num_requests}")
    print(f"Delay: {delay}s entre peticiones")
    print(f"Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()

    blocked = False
    blocked_at = 0
    successful = 0
    failed = 0

    for i in range(1, num_requests + 1):
        try:
            start_time = time.time()
            response = requests.get(url, timeout=5)
            elapsed = time.time() - start_time

            successful += 1

            # Mostrar progreso cada 10 peticiones
            if i % 10 == 0:
                print(f"[{i:3d}/{num_requests}] ✓ Status: {response.status_code} | "
                      f"Time: {elapsed:.3f}s | OK")

            time.sleep(delay)

        except requests.exceptions.Timeout:
            failed += 1
            print(f"[{i:3d}/{num_requests}] ✗ TIMEOUT - Conexión muy lenta o bloqueada")

        except requests.exceptions.ConnectionError as e:
            failed += 1
            blocked = True
            blocked_at = i

            print()
            print("=" * 60)
            print(f"🚫 ¡IP BLOQUEADA después de {i} peticiones!")
            print("=" * 60)
            print(f"Error: {str(e)[:100]}")
            print()
            print("Esto significa que Fail2ban está funcionando correctamente.")
            print("Tu IP ha sido baneada por hacer demasiadas peticiones.")
            print()
            print("Para desbloquear tu IP en el servidor:")
            print(f"  sudo fail2ban-client set nginx-req-limit unbanip $(curl -s ifconfig.me)")
            print()
            break

        except Exception as e:
            failed += 1
            print(f"[{i:3d}/{num_requests}] ✗ ERROR: {str(e)[:50]}")

    # Resumen
    print()
    print("=" * 60)
    print("RESUMEN DEL TEST")
    print("=" * 60)
    print(f"Total de peticiones intentadas: {i}")
    print(f"Peticiones exitosas: {successful}")
    print(f"Peticiones fallidas: {failed}")
    print()

    if blocked:
        print(f"✅ FAIL2BAN FUNCIONANDO: IP bloqueada en petición #{blocked_at}")
        print()
        print("Verificar en el servidor:")
        print("  sudo fail2ban-client status nginx-req-limit")
        print("  sudo tail -20 /var/log/fail2ban.log")
        return True
    else:
        print(f"❌ FAIL2BAN NO BLOQUEÓ: Completadas {successful} peticiones sin bloqueo")
        print()
        print("Posibles causas:")
        print("  1. Fail2ban no está configurado correctamente")
        print("  2. La jail nginx-req-limit no está activa")
        print("  3. El filtro no está detectando las peticiones")
        print("  4. El umbral (maxretry) es mayor que las peticiones hechas")
        print()
        print("Verificar en el servidor:")
        print("  sudo fail2ban-client status")
        print("  sudo fail2ban-client status nginx-req-limit")
        print("  sudo tail -50 /var/log/fail2ban.log")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Probar bloqueo de Fail2ban haciendo múltiples peticiones HTTP'
    )
    parser.add_argument(
        'url',
        help='URL del servidor a probar (ej: http://mi-servidor.com)'
    )
    parser.add_argument(
        '-n', '--num-requests',
        type=int,
        default=150,
        help='Número de peticiones a hacer (default: 150)'
    )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=0.05,
        help='Delay entre peticiones en segundos (default: 0.05)'
    )

    args = parser.parse_args()

    # Validar URL
    if not args.url.startswith('http'):
        print("ERROR: La URL debe comenzar con http:// o https://")
        sys.exit(1)

    # Confirmar
    print()
    print("⚠️  ADVERTENCIA ⚠️")
    print("Este script hará múltiples peticiones rápidas al servidor.")
    print("Tu IP puede ser bloqueada si Fail2ban está configurado correctamente.")
    print()
    response = input("¿Continuar? (s/n): ")

    if response.lower() != 's':
        print("Test cancelado.")
        sys.exit(0)

    print()

    # Ejecutar test
    success = test_fail2ban(args.url, args.num_requests, args.delay)

    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
