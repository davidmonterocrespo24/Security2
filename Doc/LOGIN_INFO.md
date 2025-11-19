# Sistema de Login - Instrucciones

## Descripción

Se ha implementado un sistema de autenticación completo para el Sistema de Administración de Seguridad para Ubuntu Server.

## Credenciales por Defecto

Las credenciales están configuradas en el archivo `.env`:

- **Usuario:** `admin`
- **Contraseña:** `Montero25`

## Características Implementadas

### 1. Página de Login
- Diseño profesional y moderno
- Formulario seguro con validación
- Opción "Recordar sesión"
- Mostrar/ocultar contraseña
- Mensajes de error claros
- Redirección automática después del login

### 2. Autenticación con Flask-Login
- Sistema de sesiones seguro
- Protección de todas las rutas principales
- Protección de endpoints API
- Gestión automática de sesiones

### 3. Rutas Protegidas

#### Páginas Web:
- `/` - Dashboard
- `/setup` - Configuración inicial
- `/firewall` - Gestión de firewall
- `/fail2ban` - Gestión de Fail2ban
- `/logs` - Análisis de logs
- `/threats` - Detección de amenazas
- `/settings` - Configuración

#### API Endpoints:
- `/api/config` - Configuración
- `/api/install` - Instalación
- `/api/dashboard/stats` - Estadísticas
- Y todos los demás endpoints API

### 4. Funcionalidades

- **Login:** `/login` - Página de inicio de sesión
- **Logout:** `/logout` - Cerrar sesión
- **Redirección:** Los usuarios no autenticados son redirigidos automáticamente a `/login`
- **Botón de Logout:** Disponible en el sidebar de todas las páginas

## Uso

### Iniciar el Servidor

```bash
python app.py
```

El servidor estará disponible en: `http://127.0.0.1:5000`

### Acceder al Sistema

1. Abre tu navegador y ve a `http://127.0.0.1:5000`
2. Serás redirigido automáticamente a la página de login
3. Ingresa las credenciales:
   - Usuario: `admin`
   - Contraseña: `Montero25`
4. Haz clic en "Iniciar Sesión"

### Cerrar Sesión

- Haz clic en el botón "Cerrar Sesión" en la parte inferior del sidebar
- O ve directamente a `http://127.0.0.1:5000/logout`

## Configuración Personalizada

Para cambiar las credenciales, edita el archivo `.env`:

```env
ADMIN_USERNAME=tu_usuario
ADMIN_PASSWORD=tu_contraseña
```

También puedes cambiar otras configuraciones:

```env
SECRET_KEY=tu-clave-secreta-aqui
PORT=5000
HOST=127.0.0.1
FLASK_ENV=development
```

## Seguridad

- Las sesiones están protegidas con `SECRET_KEY`
- Todas las rutas principales requieren autenticación
- Las contraseñas se validan en el servidor
- La opción "Recordar sesión" mantiene la sesión activa

## Archivos Modificados

1. **app.py** - Lógica de autenticación y rutas protegidas
2. **templates/login.html** - Página de login
3. **templates/base.html** - Botón de logout agregado
4. **.env.example** - Credenciales de ejemplo
5. **.env** - Credenciales reales (creado automáticamente)
6. **requirements.txt** - Flask-Login ya incluido

## Notas

- En Windows, `python-iptables` está comentado en `requirements.txt` porque es específico de Linux
- El servidor se ejecuta en modo de desarrollo por defecto
- Para producción, usa un servidor WSGI como Gunicorn
