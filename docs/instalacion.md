# Guía de Instalación - Sistema de Detección de Anomalías

## Requisitos del Sistema

### Software Base
- Python 3.8 o superior
- Node.js 14 o superior  
- PostgreSQL 12 o superior (producción)
- Redis 6 o superior (para tareas asíncronas)

### Herramientas Opcionales
- Wireshark/tshark (para captura real de tráfico)
- Flowmeter (para conversión PCAP a CSV)
- Docker (para contenedores)

## Instalación Paso a Paso

### 1. Clonar el Repositorio
```bash
git clone https://github.com/Rodrigo101102/deteccion-anomalia.git
cd deteccion-anomalia
```

### 2. Crear Entorno Virtual
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows
```

### 3. Instalar Dependencias Python
```bash
pip install -r requirements.txt
```

### 4. Configurar Variables de Entorno
```bash
cp .env.example .env
```

Editar `.env` con tus configuraciones:
```bash
# Base de datos
DB_NAME=anomalia_detection
DB_USER=tu_usuario
DB_PASSWORD=tu_contraseña
DB_HOST=localhost
DB_PORT=5432

# Django
SECRET_KEY=tu-clave-secreta-muy-larga-y-segura
DEBUG=False  # En producción
ALLOWED_HOSTS=tu-dominio.com,localhost

# Celery/Redis
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

### 5. Configurar Base de Datos

#### Para Desarrollo (SQLite)
```bash
python manage.py migrate
python manage.py createsuperuser
```

#### Para Producción (PostgreSQL)
1. Instalar PostgreSQL:
```bash
# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib

# CentOS/RHEL
sudo yum install postgresql-server postgresql-contrib
```

2. Crear base de datos:
```sql
sudo -u postgres psql
CREATE DATABASE anomalia_detection;
CREATE USER tu_usuario WITH PASSWORD 'tu_contraseña';
GRANT ALL PRIVILEGES ON DATABASE anomalia_detection TO tu_usuario;
ALTER USER tu_usuario CREATEDB;
\q
```

3. Instalar driver PostgreSQL:
```bash
pip install psycopg2-binary
```

4. Actualizar settings para usar PostgreSQL:
```python
# En anomalia_detection/settings/__init__.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT'),
    }
}
```

5. Ejecutar migraciones:
```bash
python manage.py migrate
python manage.py createsuperuser
```

### 6. Instalar Herramientas de Captura (Opcional)

#### Wireshark/tshark
```bash
# Ubuntu/Debian
sudo apt install wireshark tshark

# CentOS/RHEL
sudo yum install wireshark

# macOS
brew install wireshark
```

#### Flowmeter
```bash
npm install -g flowmeter
```

### 7. Configurar Redis (Para Tareas Asíncronas)
```bash
# Ubuntu/Debian
sudo apt install redis-server

# CentOS/RHEL
sudo yum install redis

# macOS
brew install redis

# Iniciar Redis
sudo systemctl start redis
# o
redis-server
```

### 8. Ejecutar el Sistema

#### Desarrollo
```bash
python manage.py runserver
```

#### Producción
```bash
# Instalar Gunicorn
pip install gunicorn

# Ejecutar con Gunicorn
gunicorn anomalia_detection.wsgi:application --bind 0.0.0.0:8000
```

#### Con Celery (Tareas Asíncronas)
En terminales separadas:
```bash
# Worker de Celery
celery -A anomalia_detection worker -l info

# Beat de Celery (tareas programadas)
celery -A anomalia_detection beat -l info
```

## Configuración de Producción

### Nginx
```nginx
server {
    listen 80;
    server_name tu-dominio.com;
    
    location /static/ {
        alias /ruta/a/tu/proyecto/staticfiles/;
    }
    
    location /media/ {
        alias /ruta/a/tu/proyecto/media/;
    }
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Systemd (Ubuntu/CentOS)
Crear `/etc/systemd/system/anomalia-detection.service`:
```ini
[Unit]
Description=Anomalia Detection Django App
After=network.target

[Service]
Type=notify
User=tu-usuario
Group=tu-grupo
RuntimeDirectory=anomalia-detection
WorkingDirectory=/ruta/a/tu/proyecto
Environment=DJANGO_SETTINGS_MODULE=anomalia_detection.settings
ExecStart=/ruta/a/tu/venv/bin/gunicorn anomalia_detection.wsgi:application --bind unix:/run/anomalia-detection/socket
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Activar el servicio:
```bash
sudo systemctl daemon-reload
sudo systemctl enable anomalia-detection
sudo systemctl start anomalia-detection
```

## Docker (Opcional)

### Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código de la aplicación
COPY . .

# Crear usuario no-root
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

# Exponer puerto
EXPOSE 8000

# Comando por defecto
CMD ["gunicorn", "anomalia_detection.wsgi:application", "--bind", "0.0.0.0:8000"]
```

### docker-compose.yml
```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=False
      - DB_HOST=db
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - ./media:/app/media
      - ./staticfiles:/app/staticfiles

  db:
    image: postgres:13
    environment:
      POSTGRES_DB: anomalia_detection
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine

  celery:
    build: .
    command: celery -A anomalia_detection worker -l info
    environment:
      - DB_HOST=db
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

volumes:
  postgres_data:
```

Ejecutar con Docker:
```bash
docker-compose up -d
```

## Verificación de la Instalación

### 1. Verificar Django
```bash
python manage.py check
```

### 2. Verificar Base de Datos
```bash
python manage.py showmigrations
```

### 3. Ejecutar Tests
```bash
python manage.py test
```

### 4. Verificar Scripts de Procesamiento
```bash
# Captura simulada
python scripts/captura_wireshark.py

# Conversión CSV
node scripts/flow.js

# Procesamiento (requiere pandas)
python scripts/procesar_csv.py

# Predicción ML (requiere scikit-learn)
python scripts/predecir_csv.py
```

### 5. Acceder a la Aplicación
- **Aplicación principal**: http://localhost:8000/
- **Panel de administración**: http://localhost:8000/admin/
- **Dashboard**: http://localhost:8000/dashboard/

## Solución de Problemas

### Error de Importación Django
```bash
# Verificar instalación
pip list | grep Django

# Reinstalar si es necesario
pip uninstall Django
pip install Django==4.2.7
```

### Error de Base de Datos
```bash
# Verificar conexión PostgreSQL
psql -h localhost -U tu_usuario -d anomalia_detection

# Regenerar migraciones si es necesario
python manage.py makemigrations
python manage.py migrate
```

### Error de Permisos tshark
```bash
# Agregar usuario al grupo wireshark
sudo usermod -a -G wireshark $USER

# O ejecutar con sudo (no recomendado en producción)
sudo python scripts/captura_wireshark.py
```

### Error de Redis/Celery
```bash
# Verificar Redis
redis-cli ping

# Verificar configuración Celery
python -c "from celery import Celery; print('OK')"
```

## Configuración de Seguridad

### 1. Variables de Entorno Seguras
- Nunca commits archivos `.env` al repositorio
- Usa gestores de secretos en producción (AWS Secrets Manager, etc.)

### 2. Permisos de Archivos
```bash
chmod 600 .env
chmod +x scripts/*.py
chmod +x scripts/*.js
```

### 3. Firewall
```bash
# Permitir solo puertos necesarios
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP
sudo ufw allow 443   # HTTPS
sudo ufw enable
```

## Mantenimiento

### Backup de Base de Datos
```bash
# PostgreSQL
pg_dump -U tu_usuario anomalia_detection > backup.sql

# Restaurar
psql -U tu_usuario anomalia_detection < backup.sql
```

### Logs del Sistema
```bash
# Ver logs de Django
tail -f logs/django.log

# Ver logs de Nginx
sudo tail -f /var/log/nginx/access.log

# Ver logs de Systemd
sudo journalctl -u anomalia-detection -f
```

### Actualización del Sistema
```bash
git pull origin main
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic --noinput
sudo systemctl restart anomalia-detection
```