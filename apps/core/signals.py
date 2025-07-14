"""
Señales de Django para el sistema.
"""

from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.utils import timezone
import logging

from .models import CustomUser, AuditLog, SystemAlert
from .utils import log_user_action, create_system_alert

logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Registra el login del usuario"""
    try:
        log_user_action(
            user=user,
            action='login',
            description=f'Usuario {user.username} inició sesión',
            request=request
        )
        
        # Actualizar estado de sesión
        user.is_active_session = True
        user.last_activity = timezone.now()
        user.save(update_fields=['is_active_session', 'last_activity'])
        
    except Exception as e:
        logger.error(f"Error logging user login: {e}")


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Registra el logout del usuario"""
    try:
        if user:
            log_user_action(
                user=user,
                action='logout',
                description=f'Usuario {user.username} cerró sesión',
                request=request
            )
            
            # Actualizar estado de sesión
            user.is_active_session = False
            user.save(update_fields=['is_active_session'])
            
    except Exception as e:
        logger.error(f"Error logging user logout: {e}")


@receiver(post_save, sender=CustomUser)
def log_user_changes(sender, instance, created, **kwargs):
    """Registra cambios en usuarios"""
    try:
        if created:
            log_user_action(
                user=None,  # Sistema
                action='user_created',
                description=f'Usuario {instance.username} creado con rol {instance.role}',
                additional_data={
                    'username': instance.username,
                    'role': instance.role,
                    'email': instance.email
                }
            )
        else:
            # Solo si hay cambios significativos
            if hasattr(instance, '_original_role'):
                if instance._original_role != instance.role:
                    log_user_action(
                        user=None,
                        action='user_modified',
                        description=f'Rol de usuario {instance.username} cambiado de {instance._original_role} a {instance.role}',
                        additional_data={
                            'username': instance.username,
                            'old_role': instance._original_role,
                            'new_role': instance.role
                        }
                    )
    except Exception as e:
        logger.error(f"Error logging user changes: {e}")


@receiver(pre_save, sender=CustomUser)
def store_original_user_data(sender, instance, **kwargs):
    """Almacena datos originales del usuario para comparación"""
    if instance.pk:
        try:
            original = CustomUser.objects.get(pk=instance.pk)
            instance._original_role = original.role
        except CustomUser.DoesNotExist:
            pass


@receiver(post_save, sender=SystemAlert)
def handle_new_alert(sender, instance, created, **kwargs):
    """Maneja nuevas alertas del sistema"""
    if created:
        try:
            logger.info(f"Nueva alerta creada: {instance.title} - Severidad: {instance.severity}")
            
            # Para alertas críticas, crear log adicional
            if instance.severity == 'critical':
                log_user_action(
                    user=None,
                    action='alert_generated',
                    description=f'Alerta crítica generada: {instance.title}',
                    additional_data={
                        'alert_id': instance.id,
                        'severity': instance.severity,
                        'alert_type': instance.alert_type
                    }
                )
        except Exception as e:
            logger.error(f"Error handling new alert: {e}")


@receiver(post_delete, sender=AuditLog)
def log_audit_deletion(sender, instance, **kwargs):
    """Registra eliminación de logs de auditoría"""
    try:
        logger.warning(f"Log de auditoría eliminado: {instance.id} - {instance.action}")
    except Exception as e:
        logger.error(f"Error logging audit deletion: {e}")


# Señal personalizada para monitoreo del sistema
from django.dispatch import Signal

system_health_check = Signal()
traffic_anomaly_detected = Signal()
model_retrained = Signal()


@receiver(traffic_anomaly_detected)
def handle_traffic_anomaly(sender, **kwargs):
    """Maneja detección de anomalías de tráfico"""
    try:
        traffic_data = kwargs.get('traffic_data')
        confidence = kwargs.get('confidence', 0.0)
        
        if confidence > 0.8:  # Alta confianza
            severity = 'high' if confidence > 0.9 else 'medium'
            
            create_system_alert(
                title=f'Anomalía de tráfico detectada',
                description=f'Se detectó tráfico anómalo con confianza {confidence:.2%}',
                severity=severity,
                alert_type='traffic_anomaly',
                source_ip=traffic_data.get('src_ip') if traffic_data else None,
                target_ip=traffic_data.get('dst_ip') if traffic_data else None,
                alert_data={
                    'confidence': confidence,
                    'traffic_id': traffic_data.get('id') if traffic_data else None
                }
            )
            
    except Exception as e:
        logger.error(f"Error handling traffic anomaly: {e}")


@receiver(model_retrained)
def handle_model_retrained(sender, **kwargs):
    """Maneja reentrenamiento del modelo"""
    try:
        model_info = kwargs.get('model_info', {})
        
        log_user_action(
            user=None,
            action='model_train',
            description='Modelo de detección de anomalías reentrenado',
            additional_data=model_info
        )
        
        create_system_alert(
            title='Modelo reentrenado',
            description='El modelo de detección de anomalías ha sido reentrenado exitosamente',
            severity='low',
            alert_type='system_info',
            alert_data=model_info
        )
        
    except Exception as e:
        logger.error(f"Error handling model retrained: {e}")


@receiver(system_health_check)
def handle_system_health_check(sender, **kwargs):
    """Maneja verificaciones de salud del sistema"""
    try:
        health_data = kwargs.get('health_data', {})
        
        # Verificar métricas críticas
        if health_data.get('disk_usage', 0) > 90:
            create_system_alert(
                title='Espacio en disco bajo',
                description=f'El uso de disco ha alcanzado {health_data["disk_usage"]}%',
                severity='high',
                alert_type='system_resource',
                alert_data=health_data
            )
        
        if health_data.get('memory_usage', 0) > 95:
            create_system_alert(
                title='Memoria alta',
                description=f'El uso de memoria ha alcanzado {health_data["memory_usage"]}%',
                severity='medium',
                alert_type='system_resource',
                alert_data=health_data
            )
            
    except Exception as e:
        logger.error(f"Error handling system health check: {e}")