"""
Señales para la aplicación traffic.
"""

from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.utils import timezone
import logging

from .models import TraficoRed, CaptureSession
from apps.core.utils import create_system_alert, log_user_action
from apps.core.signals import traffic_anomaly_detected

logger = logging.getLogger(__name__)


@receiver(post_save, sender=TraficoRed)
def handle_new_traffic_record(sender, instance, created, **kwargs):
    """Maneja nuevos registros de tráfico"""
    if created:
        try:
            # Log del nuevo registro
            logger.debug(f"Nuevo registro de tráfico: {instance.get_flow_identifier()}")
            
            # Si es una anomalía, generar alerta
            if instance.is_anomaly and instance.confidence_score and instance.confidence_score > 0.8:
                # Emitir señal de anomalía detectada
                traffic_anomaly_detected.send(
                    sender=sender,
                    traffic_data={
                        'id': instance.id,
                        'src_ip': instance.src_ip,
                        'dst_ip': instance.dst_ip,
                        'src_port': instance.src_port,
                        'dst_port': instance.dst_port,
                        'protocol': instance.protocol,
                        'label': instance.label
                    },
                    confidence=instance.confidence_score
                )
                
                # Crear alerta específica para anomalías críticas
                if instance.confidence_score > 0.9:
                    create_system_alert(
                        title=f'Anomalía crítica detectada',
                        description=f'Tráfico anómalo con alta confianza: {instance.src_ip}:{instance.src_port} -> {instance.dst_ip}:{instance.dst_port}',
                        severity='critical',
                        alert_type='traffic_anomaly',
                        source_ip=instance.src_ip,
                        target_ip=instance.dst_ip,
                        alert_data={
                            'traffic_id': instance.id,
                            'confidence': instance.confidence_score,
                            'protocol': instance.protocol,
                            'flow_id': instance.get_flow_identifier()
                        }
                    )
                    
        except Exception as e:
            logger.error(f"Error manejando nuevo registro de tráfico: {e}")


@receiver(post_save, sender=TraficoRed)
def update_traffic_statistics(sender, instance, created, **kwargs):
    """Actualiza estadísticas cuando se crea/modifica tráfico"""
    if created:
        try:
            from .tasks import actualizar_estadisticas_trafico
            # Actualizar estadísticas de forma asíncrona
            actualizar_estadisticas_trafico.delay()
        except Exception as e:
            logger.error(f"Error actualizando estadísticas: {e}")


@receiver(post_save, sender=CaptureSession)
def handle_capture_session_changes(sender, instance, created, **kwargs):
    """Maneja cambios en sesiones de captura"""
    try:
        if created:
            logger.info(f"Nueva sesión de captura creada: {instance.session_id}")
            
            # Log de auditoría
            log_user_action(
                user=instance.started_by,
                action='capture_start',
                description=f'Sesión de captura creada: {instance.session_id}',
                additional_data={
                    'session_id': instance.session_id,
                    'interface': instance.interface,
                    'duration': instance.duration
                }
            )
        
        else:
            # Verificar cambios de estado
            if hasattr(instance, '_original_status'):
                if instance._original_status != instance.status:
                    logger.info(f"Sesión {instance.session_id} cambió de {instance._original_status} a {instance.status}")
                    
                    # Crear alerta si falló
                    if instance.status == 'FAILED':
                        create_system_alert(
                            title='Captura de tráfico fallida',
                            description=f'La sesión de captura {instance.session_id} ha fallado: {instance.error_message}',
                            severity='medium',
                            alert_type='capture_error',
                            alert_data={
                                'session_id': instance.session_id,
                                'error_message': instance.error_message
                            }
                        )
                    
                    # Log de finalización exitosa
                    elif instance.status == 'COMPLETED':
                        log_user_action(
                            user=instance.started_by,
                            action='capture_completed',
                            description=f'Captura completada: {instance.session_id}',
                            additional_data={
                                'session_id': instance.session_id,
                                'packets_captured': instance.packets_captured,
                                'bytes_captured': instance.bytes_captured,
                                'duration_actual': instance.duration_actual
                            }
                        )
                        
                        # Crear alerta informativa para capturas grandes
                        if instance.packets_captured > 100000:  # Más de 100k paquetes
                            create_system_alert(
                                title='Captura grande completada',
                                description=f'Se completó una captura con {instance.packets_captured:,} paquetes',
                                severity='low',
                                alert_type='capture_info',
                                alert_data={
                                    'session_id': instance.session_id,
                                    'packets_captured': instance.packets_captured,
                                    'bytes_captured': instance.bytes_captured
                                }
                            )
                            
    except Exception as e:
        logger.error(f"Error manejando cambios en sesión de captura: {e}")


@receiver(pre_save, sender=CaptureSession)
def store_original_capture_status(sender, instance, **kwargs):
    """Almacena el estado original de la sesión de captura"""
    if instance.pk:
        try:
            original = CaptureSession.objects.get(pk=instance.pk)
            instance._original_status = original.status
        except CaptureSession.DoesNotExist:
            pass


@receiver(post_delete, sender=TraficoRed)
def handle_traffic_deletion(sender, instance, **kwargs):
    """Maneja eliminación de registros de tráfico"""
    try:
        logger.info(f"Registro de tráfico eliminado: {instance.id}")
        
        # Si era una anomalía, registrar la eliminación
        if instance.is_anomaly:
            logger.warning(f"Anomalía eliminada: {instance.get_flow_identifier()}")
            
    except Exception as e:
        logger.error(f"Error manejando eliminación de tráfico: {e}")


@receiver(post_delete, sender=CaptureSession)
def handle_capture_session_deletion(sender, instance, **kwargs):
    """Maneja eliminación de sesiones de captura"""
    try:
        logger.info(f"Sesión de captura eliminada: {instance.session_id}")
        
        # Log de auditoría
        log_user_action(
            user=None,  # Sistema
            action='capture_session_deleted',
            description=f'Sesión de captura eliminada: {instance.session_id}',
            additional_data={
                'session_id': instance.session_id,
                'status': instance.status
            }
        )
        
        # Limpiar archivos asociados si existen
        import os
        
        if instance.pcap_file_path and os.path.exists(instance.pcap_file_path):
            try:
                os.remove(instance.pcap_file_path)
                logger.info(f"Archivo PCAP eliminado: {instance.pcap_file_path}")
            except Exception as e:
                logger.error(f"Error eliminando archivo PCAP: {e}")
        
        if instance.csv_file_path and os.path.exists(instance.csv_file_path):
            try:
                os.remove(instance.csv_file_path)
                logger.info(f"Archivo CSV eliminado: {instance.csv_file_path}")
            except Exception as e:
                logger.error(f"Error eliminando archivo CSV: {e}")
                
    except Exception as e:
        logger.error(f"Error manejando eliminación de sesión de captura: {e}")


# Señales personalizadas para traffic
from django.dispatch import Signal

capture_started = Signal()
capture_completed = Signal() 
capture_failed = Signal()
high_volume_detected = Signal()
suspicious_pattern_detected = Signal()


@receiver(capture_started)
def handle_capture_started(sender, **kwargs):
    """Maneja inicio de captura"""
    try:
        session_data = kwargs.get('session_data', {})
        logger.info(f"Captura iniciada: {session_data.get('session_id')}")
        
    except Exception as e:
        logger.error(f"Error manejando inicio de captura: {e}")


@receiver(capture_completed)
def handle_capture_completed(sender, **kwargs):
    """Maneja finalización de captura"""
    try:
        session_data = kwargs.get('session_data', {})
        packets_captured = kwargs.get('packets_captured', 0)
        
        logger.info(f"Captura completada: {session_data.get('session_id')} con {packets_captured} paquetes")
        
        # Iniciar procesamiento automático si está configurado
        from apps.core.models import SystemConfiguration
        config = SystemConfiguration.get_current_config()
        
        if config.auto_process_csv:
            from .tasks import convertir_pcap_a_csv
            pcap_path = session_data.get('pcap_file_path')
            if pcap_path:
                convertir_pcap_a_csv.delay(session_data.get('session_id'), pcap_path)
                
    except Exception as e:
        logger.error(f"Error manejando finalización de captura: {e}")


@receiver(capture_failed)
def handle_capture_failed(sender, **kwargs):
    """Maneja fallo en captura"""
    try:
        session_data = kwargs.get('session_data', {})
        error_message = kwargs.get('error_message', 'Error desconocido')
        
        logger.error(f"Captura fallida: {session_data.get('session_id')} - {error_message}")
        
        # Crear alerta de error
        create_system_alert(
            title='Error en captura de tráfico',
            description=f'Falló la captura {session_data.get("session_id")}: {error_message}',
            severity='high',
            alert_type='capture_error',
            alert_data={
                'session_id': session_data.get('session_id'),
                'error': error_message
            }
        )
        
    except Exception as e:
        logger.error(f"Error manejando fallo de captura: {e}")


@receiver(high_volume_detected)
def handle_high_volume_traffic(sender, **kwargs):
    """Maneja detección de tráfico de alto volumen"""
    try:
        traffic_data = kwargs.get('traffic_data', {})
        volume = kwargs.get('volume', 0)
        
        create_system_alert(
            title='Tráfico de alto volumen detectado',
            description=f'Se detectó tráfico de {volume:,} bytes desde {traffic_data.get("src_ip")}',
            severity='medium',
            alert_type='high_volume',
            source_ip=traffic_data.get('src_ip'),
            target_ip=traffic_data.get('dst_ip'),
            alert_data={
                'volume_bytes': volume,
                'traffic_id': traffic_data.get('id')
            }
        )
        
    except Exception as e:
        logger.error(f"Error manejando tráfico de alto volumen: {e}")


@receiver(suspicious_pattern_detected)
def handle_suspicious_pattern(sender, **kwargs):
    """Maneja detección de patrones sospechosos"""
    try:
        pattern_data = kwargs.get('pattern_data', {})
        pattern_type = kwargs.get('pattern_type', 'unknown')
        
        create_system_alert(
            title=f'Patrón sospechoso detectado: {pattern_type}',
            description=f'Se detectó un patrón sospechoso en el tráfico',
            severity='medium',
            alert_type='suspicious_pattern',
            alert_data=pattern_data
        )
        
    except Exception as e:
        logger.error(f"Error manejando patrón sospechoso: {e}")