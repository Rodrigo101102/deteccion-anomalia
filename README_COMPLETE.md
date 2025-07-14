# Sistema Completo de Detección de Anomalías de Tráfico de Red

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Django](https://img.shields.io/badge/Django-4.2+-green.svg)](https://djangoproject.com)
[![Node.js](https://img.shields.io/badge/Node.js-18+-yellow.svg)](https://nodejs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

## 📋 Descripción

Sistema completo de detección de anomalías de tráfico de red que utiliza técnicas de Machine Learning para identificar patrones sospechosos en el tráfico de red. El sistema captura automáticamente tráfico usando Wireshark, procesa los datos y aplica algoritmos de detección de anomalías para identificar posibles amenazas de seguridad.

## ✨ Características Principales

- **Captura Automática**: Captura de tráfico de red usando tshark con inicio automático después de 20 segundos
- **Procesamiento Inteligente**: Conversión automática de PCAP a CSV usando Node.js
- **Machine Learning**: Detección de anomalías usando Isolation Forest
- **Dashboard Web**: Interfaz web completa con visualizaciones en tiempo real
- **Alertas**: Sistema de alertas automáticas para anomalías críticas
- **API REST**: API completa para integración con otros sistemas
- **Escalabilidad**: Arquitectura basada en Celery para procesamiento asíncrono
- **Docker**: Despliegue completo con Docker Compose

## 🏗️ Arquitectura del Sistema

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Captura de    │    │  Procesamiento  │    │   Detección     │
│    Tráfico      │───▶│      CSV        │───▶│   Anomalías     │
│   (tshark)      │    │   (Node.js)     │    │    (ML)         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Django      │    │   PostgreSQL    │    │   Dashboard     │
│   Backend       │◀──▶│   Base de       │◀──▶│     Web         │
│                 │    │     Datos       │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐
│     Celery      │
│   (Tareas       │
│   Asíncronas)   │
└─────────────────┘
```

## 🚀 Instalación Rápida con Docker

### Prerrequisitos

- Docker y Docker Compose
- Git

### Pasos de Instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/Rodrigo101102/deteccion-anomalia.git
cd deteccion-anomalia
```

2. **Configurar variables de entorno**
```bash
cp .env.example .env
# Editar .env con tus configuraciones
```

3. **Construir y ejecutar con Docker Compose**
```bash
docker-compose up --build -d
```

4. **Crear superusuario**
```bash
docker-compose exec web python manage.py createsuperuser
```

5. **Acceder al sistema**
- Dashboard: http://localhost
- Admin: http://localhost/admin
- API: http://localhost/api
- Flower (Celery): http://localhost:5555

## 🔧 Instalación Manual

### Prerrequisitos del Sistema

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    python3.11 python3.11-venv python3-pip \
    nodejs npm \
    postgresql postgresql-contrib \
    redis-server \
    tshark wireshark-common \
    build-essential

# Configurar permisos para tshark
sudo usermod -a -G wireshark $USER
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
```

### Configuración del Proyecto

1. **Crear entorno virtual**
```bash
python3.11 -m venv venv
source venv/bin/activate
```

2. **Instalar dependencias Python**
```bash
pip install -r requirements.txt
```

3. **Instalar dependencias Node.js**
```bash
npm install
```

4. **Configurar base de datos**
```bash
sudo -u postgres createdb anomalia_detection
python manage.py migrate
python manage.py createsuperuser
```

5. **Configurar servicios**
```bash
# Iniciar Redis
sudo systemctl start redis-server

# Iniciar Celery Worker
celery -A anomalia_detection worker --loglevel=info &

# Iniciar Celery Beat
celery -A anomalia_detection beat --loglevel=info &

# Iniciar servidor Django
python manage.py runserver
```

## 📁 Estructura del Proyecto

```
deteccion-anomalia/
├── manage.py                          # Django management
├── requirements.txt                   # Dependencias Python
├── package.json                       # Dependencias Node.js
├── docker-compose.yml                 # Configuración Docker
├── Dockerfile                         # Imagen Docker
│
├── anomalia_detection/               # Configuración Django
│   ├── settings/                     # Settings modulares
│   ├── urls.py                       # URLs principales
│   ├── wsgi.py                       # WSGI config
│   ├── asgi.py                       # ASGI config
│   └── celery.py                     # Configuración Celery
│
├── apps/                             # Aplicaciones Django
│   ├── core/                         # App principal
│   ├── traffic/                      # Gestión de tráfico
│   ├── prediction/                   # Sistema predicción
│   └── dashboard/                    # Dashboard web
│
├── scripts/                          # Scripts de procesamiento
│   ├── captura_wireshark.py          # Captura de tráfico
│   ├── flow.js                       # Conversión PCAP a CSV
│   ├── procesar_csv.py               # Limpieza de datos
│   └── predecir_csv.py               # Predicciones ML
│
├── static/                           # Archivos estáticos
├── templates/                        # Templates Django
├── media/                           # Archivos subidos
└── docs/                            # Documentación
```

## 🎯 Uso del Sistema

### 1. Configuración Inicial

Accede al panel de administración en `/admin` y configura:

- **Configuración del Sistema**: Intervalos de captura, interfaces de red
- **Usuarios**: Crear usuarios con roles específicos
- **Alertas**: Configurar umbrales y notificaciones

### 2. Captura de Tráfico

El sistema inicia automáticamente la captura después de 20 segundos del primer acceso. También puedes:

```bash
# Captura manual
python scripts/captura_wireshark.py --interface eth0 --duration 300

# Procesamiento manual
node scripts/flow.js --all
python scripts/procesar_csv.py --all
python scripts/predecir_csv.py --predict
```

### 3. Monitoreo

- **Dashboard Principal**: Visualiza estadísticas en tiempo real
- **Lista de Tráfico**: Explora registros con filtros avanzados
- **Alertas**: Revisa anomalías detectadas
- **Analytics**: Análisis detallado de patrones

## 🔌 API REST

### Endpoints Principales

```bash
# Obtener tráfico
GET /api/traffic/

# Estadísticas
GET /api/traffic/statistics/

# Datos en tiempo real
GET /api/traffic/realtime/

# Sesiones de captura
GET /api/traffic/capture/sessions/

# Predicciones
GET /api/prediction/
```

### Ejemplo de Uso

```python
import requests

# Obtener tráfico reciente
response = requests.get('http://localhost:8000/api/traffic/?label=ANOMALO')
anomalies = response.json()

# Iniciar captura
response = requests.post('http://localhost:8000/api/traffic/capture/start/', {
    'duration': 300,
    'interface': 'eth0'
})
```

## 🤖 Machine Learning

### Algoritmo Utilizado

- **Isolation Forest**: Algoritmo no supervisado para detección de anomalías
- **Características**: Puertos, tamaños de paquete, duración, flujos de bytes
- **Preprocessing**: Normalización con StandardScaler

### Configuración del Modelo

```python
# En apps/core/models.py - SystemConfiguration
ml_contamination = 0.1  # 10% de anomalías esperadas
retrain_interval = 3600  # Reentrenamiento cada hora
```

## 📊 Integración con Power BI

### Scripts SQL Incluidos

```sql
-- Vista para Power BI
CREATE VIEW vw_traffic_analytics AS
SELECT 
    DATE(fecha_captura) as fecha,
    EXTRACT(hour FROM fecha_captura) as hora,
    protocol,
    label,
    COUNT(*) as total_registros,
    AVG(packet_size) as avg_packet_size,
    SUM(CASE WHEN label = 'ANOMALO' THEN 1 ELSE 0 END) as anomalias
FROM traficoRed 
GROUP BY DATE(fecha_captura), EXTRACT(hour FROM fecha_captura), protocol, label;
```

## 🔒 Seguridad

### Características de Seguridad

- **Autenticación**: Sistema de usuarios con roles
- **Autorización**: Permisos granulares por función
- **CSRF Protection**: Protección contra ataques CSRF
- **Rate Limiting**: Limitación de requests por IP
- **Input Validation**: Validación exhaustiva de datos
- **Audit Logging**: Log completo de actividades

### Roles de Usuario

- **Admin**: Acceso completo al sistema
- **Analyst**: Análisis y configuración
- **Operator**: Operación diaria
- **Viewer**: Solo lectura

## 🚀 Despliegue en Producción

### Configuración de Producción

1. **Variables de Entorno**
```bash
DEBUG=False
SECRET_KEY=tu-clave-secreta-super-segura
ALLOWED_HOSTS=tu-dominio.com
DATABASE_URL=postgresql://user:pass@host:5432/db
```

2. **SSL/TLS**
```bash
# Configurar certificados SSL
SECURE_SSL_REDIRECT=True
SECURE_HSTS_SECONDS=31536000
```

## 📚 Comandos Útiles

### Gestión del Sistema

```bash
# Migraciones
python manage.py makemigrations
python manage.py migrate

# Recopilar archivos estáticos
python manage.py collectstatic

# Crear superusuario
python manage.py createsuperuser

# Ejecutar tests
python manage.py test

# Procesamiento manual
python scripts/captura_wireshark.py --help
python scripts/procesar_csv.py --help
python scripts/predecir_csv.py --help
```

### Docker

```bash
# Construir y ejecutar
docker-compose up --build -d

# Ver logs
docker-compose logs -f web
docker-compose logs -f celery

# Ejecutar comandos en contenedor
docker-compose exec web python manage.py migrate
docker-compose exec web python manage.py createsuperuser

# Detener servicios
docker-compose down
```

## 🆘 Troubleshooting

### Problemas Comunes

1. **Error de permisos tshark**
```bash
sudo usermod -a -G wireshark $USER
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
```

2. **Problemas de conexión BD**
```bash
# Verificar servicio PostgreSQL
sudo systemctl status postgresql
sudo systemctl start postgresql
```

3. **Celery no procesa tareas**
```bash
# Reiniciar Celery
pkill -f celery
celery -A anomalia_detection worker --loglevel=info
```

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT.

## 🙏 Agradecimientos

- **Django**: Framework web principal
- **Scikit-learn**: Algoritmos de Machine Learning
- **Wireshark**: Herramientas de captura de red
- **Bootstrap**: Framework CSS
- **PostgreSQL**: Sistema de base de datos

---

**Desarrollado con ❤️ para la seguridad de redes**