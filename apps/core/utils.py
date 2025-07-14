"""
Utilidades generales para el sistema.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Obtiene la IP real del cliente"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """Obtiene el user agent del cliente"""
    return request.META.get('HTTP_USER_AGENT', '')


def log_user_action(user, action, description, request=None, additional_data=None):
    """Registra una acción del usuario en el log de auditoría"""
    from .models import AuditLog
    
    try:
        log_data = {
            'user': user,
            'action': action,
            'description': description,
            'additional_data': additional_data or {}
        }
        
        if request:
            log_data.update({
                'ip_address': get_client_ip(request),
                'user_agent': get_user_agent(request)
            })
        
        AuditLog.objects.create(**log_data)
        
    except Exception as e:
        logger.error(f"Error logging user action: {e}")


def create_system_alert(title, description, severity='medium', alert_type='system', 
                       source_ip=None, target_ip=None, alert_data=None):
    """Crea una alerta del sistema"""
    from .models import SystemAlert
    
    try:
        alert = SystemAlert.objects.create(
            title=title,
            description=description,
            severity=severity,
            alert_type=alert_type,
            source_ip=source_ip,
            target_ip=target_ip,
            alert_data=alert_data or {}
        )
        
        # Enviar notificación si está configurado
        if should_send_alert_notification(severity):
            send_alert_notification(alert)
        
        return alert
        
    except Exception as e:
        logger.error(f"Error creating system alert: {e}")
        return None


def should_send_alert_notification(severity):
    """Determina si debe enviar notificación para la severidad dada"""
    from .models import SystemConfiguration
    
    config = SystemConfiguration.get_current_config()
    if not config.email_alerts:
        return False
    
    # Enviar solo para alertas high y critical
    return severity in ['high', 'critical']


def send_alert_notification(alert):
    """Envía notificación por email de una alerta"""
    try:
        # Obtener usuarios que deben recibir notificaciones
        admin_users = User.objects.filter(
            role__in=['admin', 'analyst'],
            is_active=True,
            email__isnull=False
        ).exclude(email='')
        
        if not admin_users.exists():
            return
        
        # Preparar email
        subject = f"[Alerta {alert.get_severity_display()}] {alert.title}"
        
        context = {
            'alert': alert,
            'severity_color': get_severity_color(alert.severity),
        }
        
        message = render_to_string('core/email/alert_notification.html', context)
        
        recipient_list = [user.email for user in admin_users]
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_list,
            html_message=message,
            fail_silently=True
        )
        
        logger.info(f"Alert notification sent for alert {alert.id}")
        
    except Exception as e:
        logger.error(f"Error sending alert notification: {e}")


def get_severity_color(severity):
    """Obtiene el color asociado a una severidad"""
    colors = {
        'low': '#28a745',      # verde
        'medium': '#ffc107',   # amarillo
        'high': '#fd7e14',     # naranja
        'critical': '#dc3545'  # rojo
    }
    return colors.get(severity, '#6c757d')


def get_system_stats():
    """Obtiene estadísticas generales del sistema"""
    from apps.traffic.models import TraficoRed
    from apps.prediction.models import ModeloPrediccion
    from .models import SystemAlert, AuditLog
    
    try:
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        stats = {
            'traffic': {
                'total': TraficoRed.objects.count(),
                'last_24h': TraficoRed.objects.filter(fecha_captura__gte=last_24h).count(),
                'anomalies_24h': TraficoRed.objects.filter(
                    fecha_captura__gte=last_24h,
                    label='ANOMALO'
                ).count(),
            },
            'predictions': {
                'total': ModeloPrediccion.objects.count(),
                'last_24h': ModeloPrediccion.objects.filter(fecha_prediccion__gte=last_24h).count(),
            },
            'alerts': {
                'total': SystemAlert.objects.count(),
                'active': SystemAlert.objects.filter(status='active').count(),
                'critical': SystemAlert.objects.filter(
                    status='active',
                    severity='critical'
                ).count(),
                'last_7d': SystemAlert.objects.filter(created_at__gte=last_7d).count(),
            },
            'audit': {
                'total': AuditLog.objects.count(),
                'last_24h': AuditLog.objects.filter(timestamp__gte=last_24h).count(),
            },
            'users': {
                'total': User.objects.count(),
                'active': User.objects.filter(is_active=True).count(),
                'online': User.objects.filter(
                    is_active_session=True,
                    last_activity__gte=now - timedelta(minutes=30)
                ).count(),
            }
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return {}


def cleanup_old_data():
    """Limpia datos antiguos según configuración de retención"""
    from .models import SystemConfiguration, AuditLog, SystemAlert
    from apps.traffic.models import TraficoRed
    
    try:
        config = SystemConfiguration.get_current_config()
        cutoff_date = timezone.now() - timedelta(days=config.retention_days)
        
        # Limpiar logs de auditoría antiguos
        old_logs = AuditLog.objects.filter(timestamp__lt=cutoff_date)
        logs_count = old_logs.count()
        old_logs.delete()
        
        # Limpiar alertas resueltas antiguas
        old_alerts = SystemAlert.objects.filter(
            resolved_at__lt=cutoff_date,
            status__in=['resolved', 'false_positive']
        )
        alerts_count = old_alerts.count()
        old_alerts.delete()
        
        # Limpiar tráfico antiguo sin anomalías
        old_traffic = TraficoRed.objects.filter(
            fecha_captura__lt=cutoff_date,
            label='NORMAL'
        )
        traffic_count = old_traffic.count()
        old_traffic.delete()
        
        logger.info(f"Cleanup completed: {logs_count} logs, {alerts_count} alerts, {traffic_count} traffic records")
        
        return {
            'logs_deleted': logs_count,
            'alerts_deleted': alerts_count,
            'traffic_deleted': traffic_count
        }
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        return {}


def format_bytes(bytes_value):
    """Formatea bytes en unidades legibles"""
    if bytes_value == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    
    while bytes_value >= 1024 and unit_index < len(units) - 1:
        bytes_value /= 1024
        unit_index += 1
    
    return f"{bytes_value:.2f} {units[unit_index]}"


def format_duration(seconds):
    """Formatea duración en formato legible"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        return f"{int(minutes)}m {int(remaining_seconds)}s"
    else:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        return f"{int(hours)}h {int(remaining_minutes)}m"


def validate_ip_address(ip):
    """Valida una dirección IP"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip):
    """Verifica si una IP es privada"""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def export_data_to_csv(queryset, fields, filename=None):
    """Exporta datos a CSV"""
    import csv
    from django.http import HttpResponse
    
    if filename is None:
        filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    writer = csv.writer(response)
    
    # Escribir headers
    headers = [field.replace('_', ' ').title() for field in fields]
    writer.writerow(headers)
    
    # Escribir datos
    for obj in queryset:
        row = []
        for field in fields:
            value = getattr(obj, field, '')
            if hasattr(value, 'strftime'):  # Fecha/hora
                value = value.strftime('%Y-%m-%d %H:%M:%S')
            row.append(str(value))
        writer.writerow(row)
    
    return response


def generate_report_context():
    """Genera contexto para reportes"""
    stats = get_system_stats()
    
    context = {
        'generated_at': timezone.now(),
        'stats': stats,
        'period': '24 horas',
    }
    
    return context