from django.db import models


class DashboardWidget(models.Model):
    """Widget personalizable para el dashboard"""
    name = models.CharField(max_length=100)
    widget_type = models.CharField(
        max_length=50,
        choices=[
            ('chart', 'Gráfico'),
            ('table', 'Tabla'),
            ('metric', 'Métrica'),
            ('alert', 'Alerta'),
        ]
    )
    config = models.JSONField(default=dict)
    position_x = models.IntegerField(default=0)
    position_y = models.IntegerField(default=0)
    width = models.IntegerField(default=6)
    height = models.IntegerField(default=4)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'dashboard_widgets'
        verbose_name = 'Widget del Dashboard'
        verbose_name_plural = 'Widgets del Dashboard'
    
    def __str__(self):
        return self.name


class UserDashboardPreference(models.Model):
    """Preferencias de dashboard por usuario"""
    user = models.OneToOneField(
        'core.CustomUser',
        on_delete=models.CASCADE,
        related_name='dashboard_preferences'
    )
    theme = models.CharField(
        max_length=20,
        choices=[
            ('light', 'Claro'),
            ('dark', 'Oscuro'),
        ],
        default='light'
    )
    default_view = models.CharField(
        max_length=50,
        choices=[
            ('overview', 'Resumen'),
            ('traffic', 'Tráfico'),
            ('alerts', 'Alertas'),
        ],
        default='overview'
    )
    auto_refresh = models.BooleanField(default=True)
    refresh_interval = models.IntegerField(default=30)  # segundos
    
    class Meta:
        db_table = 'user_dashboard_preferences'
        verbose_name = 'Preferencia de Dashboard'
        verbose_name_plural = 'Preferencias de Dashboard'