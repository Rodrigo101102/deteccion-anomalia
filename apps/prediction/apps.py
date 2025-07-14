"""
Configuración de la app prediction.
"""
from django.apps import AppConfig


class PredictionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.prediction'
    verbose_name = 'Predicción de Anomalías'