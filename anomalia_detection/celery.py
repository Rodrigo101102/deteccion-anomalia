"""
Configuración de Celery para tareas asíncronas.
"""

import os
from celery import Celery
from django.conf import settings

# Establecer la configuración por defecto de Django para Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'anomalia_detection.settings.development')

app = Celery('anomalia_detection')

# Usar la configuración de Django como configuración de Celery
app.config_from_object('django.conf:settings', namespace='CELERY')

# Autodiscovery de tareas en todas las apps instaladas
app.autodiscover_tasks()

# Configuración de tareas periódicas
app.conf.beat_schedule = {
    'capturar-trafico-periodico': {
        'task': 'apps.traffic.tasks.capturar_trafico_automatico',
        'schedule': settings.CAPTURE_SETTINGS['INTERVAL'],
    },
    'procesar-csv-pendientes': {
        'task': 'apps.traffic.tasks.procesar_csv_pendientes',
        'schedule': 60.0,  # Cada minuto
    },
    'predecir-anomalias': {
        'task': 'apps.prediction.tasks.predecir_anomalias_pendientes',
        'schedule': 30.0,  # Cada 30 segundos
    },
    'limpiar-archivos-antiguos': {
        'task': 'apps.traffic.tasks.limpiar_archivos_antiguos',
        'schedule': 3600.0,  # Cada hora
    },
    'reentrenar-modelo': {
        'task': 'apps.prediction.tasks.reentrenar_modelo_periodico',
        'schedule': settings.ML_SETTINGS['RETRAIN_INTERVAL'],
    },
}

app.conf.timezone = settings.TIME_ZONE

@app.task(bind=True)
def debug_task(self):
    """Tarea de debug para verificar funcionamiento de Celery"""
    print(f'Request: {self.request!r}')