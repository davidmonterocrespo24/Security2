# 🎯 Cómo Usar la Integración Zeek + ML desde el Panel Web

## ✅ Todo está listo - Solo sigue estos pasos:

### Paso 1: Actualizar el servidor

```bash
ssh root@195.26.243.120
cd /home/Security2
git pull
```

### Paso 2: Reiniciar el servidor Flask

```bash
# Detener el servidor actual
pkill -9 -f 'python.*app.py'

# Iniciar el servidor nuevo
cd /home/Security2
source .venv/bin/activate
nohup python app.py > flask_server.log 2>&1 &

# Verificar que esté corriendo
ps aux | grep '[p]ython.*app.py'
```

### Paso 3: Abrir el panel web

1. Abre tu navegador
2. Ve a: `http://195.26.243.120:5000`
3. Inicia sesión

### Paso 4: Inicializar Tareas Automáticas

1. En el menú lateral, ve a: **Sistema** → **Tareas Programadas**
2. Haz clic en el botón azul **"Inicializar Tareas"**
3. Confirma

Esto creará 3 tareas automáticas:
- ✅ **Zeek Log Import** - Cada 5 minutos
- ✅ **Zeek Threat Detection** - Cada 5 minutos
- ✅ **ML Model Training** - Diario a las 3 AM

### Paso 5: (Opcional) Ejecutar tareas manualmente

En la página de "Tareas Programadas" puedes:

- **▶ Ejecutar** - Ejecutar la tarea inmediatamente (botón azul con rayo)
- **⏸ Pausar** - Detener la tarea temporalmente
- **▶ Reanudar** - Volver a activar la tarea

---

## 📊 Qué hace cada tarea

### 1. Zeek Log Import (Cada 5 minutos)
- Importa hasta 1000 logs nuevos de Zeek
- Guarda conexiones, DNS, HTTP, SSL en la base de datos
- Alimenta el sistema de análisis

### 2. Zeek Threat Detection (Cada 5 minutos)
- Analiza los logs de Zeek buscando:
  * Port scans (15+ puertos)
  * DNS tunneling (exfiltración de datos)
  * DGA domains (malware)
  * Beaconing (C&C botnets)
  * Certificados SSL inválidos
- **Crea eventos automáticamente** en `security_events`
- Estos eventos alimentan el ML

### 3. ML Model Training (Diario a las 3 AM)
- Re-entrena el modelo ML con datos nuevos
- Incluye 33 características (15 + 18 de Zeek)
- Mejora la precisión automáticamente

---

## 🎯 Ver Resultados

### Ver IPs Sospechosas Detectadas

1. Ve a: **Machine Learning** → **Sugerencias ML**
2. Verás IPs rankeadas por Threat Score
3. Con características de Zeek incluidas

### Ver Detecciones de Zeek

1. Ve a: **Network Monitor** → **Detecciones**
2. Verás:
   - Port scans detectados
   - DNS tunneling
   - Beaconing
   - SSL issues

### Ver Logs de Zeek

1. Ve a: **Network Monitor** → **Logs de Zeek**
2. Pestañas:
   - Conexiones
   - DNS
   - HTTP
   - SSL

---

## 🔧 Gestión de Tareas desde el Panel Web

### Ver Estado de las Tareas

En **Tareas Programadas** verás para cada tarea:
- ✅ **Estado**: Activa / Pausada / Ejecutando
- ⏰ **Programación**: Cada 5 minutos / Diario
- ✓ **Éxitos**: Número de ejecuciones exitosas
- ✗ **Errores**: Número de fallos
- 🕐 **Última ejecución**: Cuándo se ejecutó por última vez

### Ejecutar Tarea Manualmente

1. Haz clic en el botón **⚡ Ejecutar** (azul)
2. Espera unos segundos
3. Verás una notificación con el resultado

### Pausar/Reanudar Tarea

1. Haz clic en **⏸** para pausar (botón amarillo)
2. Haz clic en **▶** para reanudar (botón verde)

---

## 🎨 Próximas Mejoras (Si quieres)

Si necesitas algo más, puedo implementar:

1. **Dashboard mejorado** con métricas de Zeek+ML combinadas
2. **Alertas por email/Telegram** cuando se detecten amenazas críticas
3. **Auto-bloqueo** de IPs con Threat Score > 80
4. **Reportes semanales** automáticos por email
5. **Gestión avanzada de tareas** (logs de ejecución, gráficos, etc.)

---

## ✅ Resumen

**Antes**: Necesitabas scripts bash, crontab, ssh para gestionar todo

**Ahora**:
- ✅ Todo desde el panel web
- ✅ Un solo clic para inicializar
- ✅ Ver estado en tiempo real
- ✅ Ejecutar/pausar tareas cuando quieras
- ✅ Sistema completamente automatizado

**¡Tu VPS ahora tiene protección empresarial con gestión web!** 🛡️
