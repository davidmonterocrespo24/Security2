#!/usr/bin/env python3
"""
Script para descargar la base de datos GeoLite2-Country de MaxMind
MaxMind ahora requiere un account gratuito para descargar las bases de datos
"""
import os
import sys
import requests
import tarfile
import shutil
from pathlib import Path


def download_geoip_database(license_key=None):
    """
    Descargar base de datos GeoIP2 de MaxMind

    Args:
        license_key: License key de MaxMind (opcional si se usa variable de entorno)
    """
    # Directorio de datos
    data_dir = Path(__file__).parent.parent / 'data'
    data_dir.mkdir(exist_ok=True)

    # Archivo de destino
    db_file = data_dir / 'GeoLite2-Country.mmdb'

    # Si ya existe y es reciente (menos de 30 días), no descargar
    if db_file.exists():
        age_days = (Path(db_file).stat().st_mtime - os.path.getmtime(db_file)) / 86400
        if age_days < 30:
            print(f"✅ Base de datos GeoIP2 ya existe y es reciente ({age_days:.0f} días)")
            print(f"   Ubicación: {db_file}")
            return True

    # Obtener license key
    if not license_key:
        license_key = os.environ.get('MAXMIND_LICENSE_KEY')

    if not license_key:
        print("\n⚠️  MaxMind requiere una license key gratuita para descargar GeoLite2")
        print("\n📝 Para obtener una license key:")
        print("   1. Crea una cuenta gratuita en: https://www.maxmind.com/en/geolite2/signup")
        print("   2. Genera una license key en: https://www.maxmind.com/en/accounts/current/license-key")
        print("   3. Configura la variable de entorno:")
        print("      export MAXMIND_LICENSE_KEY='tu_license_key'")
        print("   4. O ejecuta este script con la key:")
        print("      python scripts/download_geoip_db.py TU_LICENSE_KEY")
        print("\n💡 Alternativamente, puedes descargar manualmente:")
        print(f"   1. Descarga desde: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        print(f"   2. Extrae GeoLite2-Country.mmdb")
        print(f"   3. Colócalo en: {db_file}")
        return False

    print("\n🌍 Descargando base de datos GeoLite2-Country...")

    # URL de descarga de MaxMind
    edition_id = 'GeoLite2-Country'
    url = f'https://download.maxmind.com/app/geoip_download?edition_id={edition_id}&license_key={license_key}&suffix=tar.gz'

    try:
        # Descargar archivo
        print("   Descargando...")
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()

        # Guardar archivo temporal
        temp_file = data_dir / f'{edition_id}.tar.gz'
        with open(temp_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        print("   Extrayendo...")
        # Extraer archivo tar.gz
        with tarfile.open(temp_file, 'r:gz') as tar:
            # Buscar el archivo .mmdb dentro del tar
            mmdb_members = [m for m in tar.getmembers() if m.name.endswith('.mmdb')]

            if not mmdb_members:
                print("❌ Error: No se encontró archivo .mmdb en el archivo descargado")
                return False

            # Extraer el primer .mmdb encontrado
            mmdb_member = mmdb_members[0]
            tar.extract(mmdb_member, data_dir)

            # Mover al destino final
            extracted_file = data_dir / mmdb_member.name
            shutil.move(str(extracted_file), str(db_file))

            # Limpiar directorio extraído
            extracted_dir = data_dir / mmdb_member.name.split('/')[0]
            if extracted_dir.exists() and extracted_dir.is_dir():
                shutil.rmtree(extracted_dir)

        # Eliminar archivo temporal
        temp_file.unlink()

        print(f"\n✅ Base de datos descargada exitosamente")
        print(f"   Ubicación: {db_file}")
        print(f"   Tamaño: {db_file.stat().st_size / 1024 / 1024:.1f} MB")

        return True

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print("\n❌ Error: License key inválida")
            print("   Verifica que la license key sea correcta")
        else:
            print(f"\n❌ Error HTTP: {e}")
        return False

    except Exception as e:
        print(f"\n❌ Error descargando base de datos: {e}")
        return False


def check_geoip_installation():
    """Verificar que geoip2 esté instalado"""
    try:
        import geoip2.database
        print("✅ Librería geoip2 instalada")
        return True
    except ImportError:
        print("❌ Librería geoip2 NO instalada")
        print("   Instala con: pip install geoip2 maxminddb")
        return False


if __name__ == '__main__':
    print("=" * 60)
    print("DESCARGA DE BASE DE DATOS GEOIP2")
    print("=" * 60)

    # Verificar instalación de geoip2
    if not check_geoip_installation():
        sys.exit(1)

    # Obtener license key de argumentos o variable de entorno
    license_key = sys.argv[1] if len(sys.argv) > 1 else None

    # Descargar base de datos
    success = download_geoip_database(license_key)

    if success:
        print("\n🎉 ¡Configuración completada!")
        print("\nAhora puedes usar el filtrado geográfico en el sistema de seguridad")
        sys.exit(0)
    else:
        print("\n⚠️  La base de datos no se pudo descargar automáticamente")
        print("   Sigue las instrucciones anteriores para configurarla manualmente")
        sys.exit(1)
