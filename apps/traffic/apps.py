from django.apps import AppConfig


class TrafficConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.traffic'
    verbose_name = 'Gestión de Tráfico de Red'
    
    def ready(self):
        """Configuración que se ejecuta cuando la app está lista"""
        import apps.traffic.signals  # Importar señales