# Sistema de Detección de Anomalías de Tráfico de Red

Una aplicación web completa desarrollada con Django para la detección automática de anomalías en el tráfico de red mediante un pipeline de captura, procesamiento y análisis de datos con Machine Learning.

## Características Principales

- **Captura Automática**: Sistema que inicia captura de tráfico después de 20 segundos
- **Pipeline Completo**: Procesamiento automatizado desde PCAP hasta predicciones ML
- **Dashboard Interactivo**: Interface web con Bootstrap y visualizaciones en tiempo real
- **Machine Learning**: Detección de anomalías usando algoritmos avanzados
- **Multi-usuario**: Sistema de roles (Administrador/Usuario) con autenticación
- **Base de Datos**: PostgreSQL optimizada para análisis de tráfico
- **Procesamiento Asíncrono**: Celery y Redis para tareas en background

## Instalación Rápida

1. **Instalar dependencias**:
```bash
pip install -r requirements.txt
```

2. **Configurar variables de entorno**:
```bash
cp .env.example .env
# Editar .env con sus configuraciones
```

3. **Ejecutar migraciones**:
```bash
python manage.py migrate
python manage.py createsuperuser
```

4. **Iniciar servidor**:
```bash
python manage.py runserver
```

## Pipeline de Procesamiento

1. **Captura**: `python scripts/captura_wireshark.py`
2. **Conversión**: `node scripts/flow.js`
3. **Limpieza**: `python scripts/procesar_csv.py`
4. **Predicción**: `python scripts/predecir_csv.py`

## Acceso al Sistema

- **URL**: http://localhost:8000/
- **Admin**: http://localhost:8000/admin/
- **Dashboard**: http://localhost:8000/dashboard/

Desarrollado para la detección automática de anomalías en redes empresariales.
