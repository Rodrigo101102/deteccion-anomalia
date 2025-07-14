from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'
    verbose_name = 'Configuración Principal'
    
    def ready(self):
        """Configuración que se ejecuta cuando la app está lista"""
        import apps.core.signals  # Importar señales