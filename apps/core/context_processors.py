"""
Context processors para templates.
"""

from django.conf import settings
from .models import SystemConfiguration, SystemAlert
from .utils import get_system_stats


def system_context(request):
    """Context processor que añade información del sistema a todos los templates"""
    
    context = {
        'system_name': 'Sistema de Detección de Anomalías',
        'system_version': '1.0.0',
    }
    
    # Solo añadir información adicional si el usuario está autenticado
    if request.user.is_authenticated:
        try:
            # Configuración del sistema
            config = SystemConfiguration.get_current_config()
            
            # Alertas activas
            active_alerts = SystemAlert.objects.filter(status='active').count()
            critical_alerts = SystemAlert.objects.filter(
                status='active',
                severity='critical'
            ).count()
            
            context.update({
                'system_config': config,
                'active_alerts_count': active_alerts,
                'critical_alerts_count': critical_alerts,
                'user_role': request.user.role,
                'user_permissions': {
                    'can_manage_users': request.user.can_manage_users(),
                    'can_modify_config': request.user.can_modify_config(),
                    'can_view_analytics': request.user.can_view_analytics(),
                }
            })
            
        except Exception:
            # En caso de error, no romper el template
            pass
    
    return context