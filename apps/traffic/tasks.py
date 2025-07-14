"""
Tareas asíncronas para la gestión de tráfico.
"""

import os
import subprocess
import logging
from datetime import datetime, timedelta
from celery import shared_task
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail

from .models import TraficoRed, CaptureSession, TrafficStatistics
from apps.core.models import SystemConfiguration, SystemAlert
from apps.core.utils import create_system_alert, log_user_action

logger = logging.getLogger(__name__)


@shared_task(bind=True)
def iniciar_captura_trafico(self, session_id):
    """
    Tarea para iniciar captura de tráfico usando tshark
    """
    try:
        # Obtener sesión de captura
        capture_session = CaptureSession.objects.get(session_id=session_id)
        
        # Marcar como iniciada
        capture_session.start_capture()
        
        # Configuración de captura
        config = SystemConfiguration.get_current_config()
        interface = capture_session.interface
        duration = capture_session.duration
        
        # Crear directorio de capturas si no existe
        capture_dir = settings.CAPTURE_SETTINGS['CAPTURE_DIR']
        os.makedirs(capture_dir, exist_ok=True)
        
        # Generar nombre de archivo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = f"captura_{session_id}_{timestamp}.pcap"
        pcap_filepath = os.path.join(capture_dir, pcap_filename)
        
        # Comando tshark
        cmd = [
            "tshark",
            "-i", interface,
            "-a", f"duration:{duration}",
            "-w", pcap_filepath,
            "-q"  # Modo silencioso
        ]
        
        logger.info(f"Iniciando captura: {' '.join(cmd)}")
        
        # Ejecutar captura
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 30  # Timeout adicional
        )
        
        if process.returncode == 0:
            # Captura exitosa
            if os.path.exists(pcap_filepath):
                file_size = os.path.getsize(pcap_filepath)
                
                # Estimar número de paquetes (aproximado)
                estimated_packets = file_size // 100  # Estimación muy básica
                
                capture_session.pcap_file_path = pcap_filepath
                capture_session.complete_capture(
                    packets=estimated_packets,
                    bytes_captured=file_size
                )
                
                logger.info(f"Captura completada: {pcap_filepath}")
                
                # Iniciar conversión a CSV automáticamente
                convertir_pcap_a_csv.delay(session_id, pcap_filepath)
                
            else:
                raise Exception("Archivo PCAP no fue creado")
        else:
            error_msg = process.stderr or "Error desconocido en tshark"
            raise Exception(f"Error en tshark: {error_msg}")
    
    except subprocess.TimeoutExpired:
        error_msg = f"Timeout en captura después de {duration + 30} segundos"
        logger.error(error_msg)
        capture_session.fail_capture(error_msg)
    
    except CaptureSession.DoesNotExist:
        error_msg = f"Sesión de captura {session_id} no encontrada"
        logger.error(error_msg)
        
    except Exception as e:
        error_msg = f"Error en captura: {str(e)}"
        logger.error(error_msg)
        
        try:
            capture_session.fail_capture(error_msg)
        except:
            pass
        
        # Crear alerta de error
        create_system_alert(
            title='Error en captura de tráfico',
            description=f'Falló la captura {session_id}: {error_msg}',
            severity='high',
            alert_type='capture_error',
            alert_data={'session_id': session_id, 'error': error_msg}
        )


@shared_task(bind=True)
def convertir_pcap_a_csv(self, session_id, pcap_filepath):
    """
    Tarea para convertir archivo PCAP a CSV usando flowmeter
    """
    try:
        # Verificar que el archivo PCAP existe
        if not os.path.exists(pcap_filepath):
            raise Exception(f"Archivo PCAP no encontrado: {pcap_filepath}")
        
        # Directorio de salida CSV
        csv_dir = settings.CAPTURE_SETTINGS['CSV_DIR']
        os.makedirs(csv_dir, exist_ok=True)
        
        # Generar nombre de archivo CSV
        pcap_basename = os.path.basename(pcap_filepath)
        csv_filename = pcap_basename.replace('.pcap', '.csv')
        csv_filepath = os.path.join(csv_dir, csv_filename)
        
        # Comando flowmeter (usar Node.js script)
        flow_script = os.path.join(settings.BASE_DIR, 'scripts', 'flow.js')
        
        cmd = [
            "node",
            flow_script,
            "--input", pcap_filepath,
            "--output", csv_filepath
        ]
        
        logger.info(f"Convirtiendo PCAP a CSV: {' '.join(cmd)}")
        
        # Ejecutar conversión
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutos timeout
        )
        
        if process.returncode == 0 and os.path.exists(csv_filepath):
            # Actualizar sesión de captura
            capture_session = CaptureSession.objects.get(session_id=session_id)
            capture_session.csv_file_path = csv_filepath
            capture_session.save()
            
            logger.info(f"Conversión completada: {csv_filepath}")
            
            # Procesar CSV automáticamente
            procesar_archivo_csv.delay(csv_filepath)
            
        else:
            error_msg = process.stderr or "Error en conversión PCAP a CSV"
            raise Exception(error_msg)
            
    except Exception as e:
        error_msg = f"Error convirtiendo PCAP a CSV: {str(e)}"
        logger.error(error_msg)
        
        create_system_alert(
            title='Error en conversión PCAP a CSV',
            description=error_msg,
            severity='medium',
            alert_type='processing_error',
            alert_data={'session_id': session_id, 'pcap_file': pcap_filepath}
        )


@shared_task(bind=True)
def procesar_archivo_csv(self, csv_filepath):
    """
    Tarea para procesar archivo CSV y cargar datos en la base de datos
    """
    try:
        import pandas as pd
        
        # Verificar que el archivo existe
        if not os.path.exists(csv_filepath):
            raise Exception(f"Archivo CSV no encontrado: {csv_filepath}")
        
        logger.info(f"Procesando archivo CSV: {csv_filepath}")
        
        # Leer CSV
        df = pd.read_csv(csv_filepath)
        
        if df.empty:
            logger.warning(f"Archivo CSV vacío: {csv_filepath}")
            return
        
        # Mapeo de columnas (ajustar según formato de flowmeter)
        column_mapping = {
            'src_ip': 'src_ip',
            'dst_ip': 'dst_ip',
            'src_port': 'src_port',
            'dst_port': 'dst_port',
            'protocol': 'protocol',
            'total_length': 'packet_size',
            'duration': 'duration',
            'flow_bytes_s': 'flow_bytes_per_sec',
            'flow_packets_s': 'flow_packets_per_sec',
            'total_fwd_packets': 'total_fwd_packets',
            'total_backward_packets': 'total_backward_packets',
        }
        
        # Renombrar columnas
        available_columns = {k: v for k, v in column_mapping.items() if k in df.columns}
        df_renamed = df.rename(columns=available_columns)
        
        # Limpiar y validar datos
        df_clean = limpiar_datos_csv(df_renamed)
        
        # Cargar datos en la base de datos
        registros_creados = 0
        archivo_origen = os.path.basename(csv_filepath)
        
        for _, row in df_clean.iterrows():
            try:
                # Preparar datos para crear registro
                record_data = {
                    'src_ip': row.get('src_ip', '0.0.0.0'),
                    'dst_ip': row.get('dst_ip', '0.0.0.0'),
                    'src_port': int(row.get('src_port', 0)),
                    'dst_port': int(row.get('dst_port', 0)),
                    'protocol': str(row.get('protocol', 'TCP'))[:10],
                    'packet_size': int(row.get('packet_size', 0)),
                    'duration': float(row.get('duration', 0.0)),
                    'flow_bytes_per_sec': float(row.get('flow_bytes_per_sec', 0.0)),
                    'flow_packets_per_sec': float(row.get('flow_packets_per_sec', 0.0)),
                    'total_fwd_packets': int(row.get('total_fwd_packets', 0)),
                    'total_backward_packets': int(row.get('total_backward_packets', 0)),
                    'archivo_origen': archivo_origen,
                    'procesado': False
                }
                
                # Crear registro
                TraficoRed.objects.create(**record_data)
                registros_creados += 1
                
            except Exception as e:
                logger.warning(f"Error procesando fila: {e}")
                continue
        
        logger.info(f"Procesamiento completado. {registros_creados} registros creados desde {csv_filepath}")
        
        # Mover archivo a directorio de procesados
        marcar_csv_como_procesado(csv_filepath)
        
        # Actualizar estadísticas
        actualizar_estadisticas_trafico.delay()
        
        return registros_creados
        
    except Exception as e:
        error_msg = f"Error procesando CSV {csv_filepath}: {str(e)}"
        logger.error(error_msg)
        
        create_system_alert(
            title='Error procesando archivo CSV',
            description=error_msg,
            severity='medium',
            alert_type='processing_error',
            alert_data={'csv_file': csv_filepath}
        )


def limpiar_datos_csv(df):
    """Limpia y valida datos del DataFrame"""
    # Eliminar filas con IPs nulas
    df = df.dropna(subset=['src_ip', 'dst_ip'])
    
    # Validar tipos de datos
    numeric_columns = ['src_port', 'dst_port', 'packet_size', 'duration', 
                      'flow_bytes_per_sec', 'flow_packets_per_sec']
    
    for col in numeric_columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    # Validar rangos de puertos
    if 'src_port' in df.columns:
        df = df[(df['src_port'] >= 0) & (df['src_port'] <= 65535)]
    if 'dst_port' in df.columns:
        df = df[(df['dst_port'] >= 0) & (df['dst_port'] <= 65535)]
    
    # Validar valores no negativos
    for col in ['packet_size', 'duration', 'flow_bytes_per_sec', 'flow_packets_per_sec']:
        if col in df.columns:
            df = df[df[col] >= 0]
    
    return df


def marcar_csv_como_procesado(csv_filepath):
    """Mueve archivo CSV a directorio de procesados"""
    try:
        processed_dir = os.path.join(
            settings.CAPTURE_SETTINGS['CSV_DIR'], 
            'processed'
        )
        os.makedirs(processed_dir, exist_ok=True)
        
        filename = os.path.basename(csv_filepath)
        new_path = os.path.join(processed_dir, filename)
        
        # Mover archivo
        os.rename(csv_filepath, new_path)
        logger.info(f"Archivo CSV movido a procesados: {new_path}")
        
    except Exception as e:
        logger.error(f"Error moviendo archivo CSV: {e}")


@shared_task
def procesar_csv_pendientes():
    """
    Tarea para procesar todos los archivos CSV pendientes
    """
    try:
        csv_dir = settings.CAPTURE_SETTINGS['CSV_DIR']
        
        if not os.path.exists(csv_dir):
            logger.info("Directorio CSV no existe")
            return
        
        # Buscar archivos CSV pendientes
        csv_files = [f for f in os.listdir(csv_dir) 
                    if f.endswith('.csv') and os.path.isfile(os.path.join(csv_dir, f))]
        
        if not csv_files:
            logger.info("No hay archivos CSV pendientes")
            return
        
        logger.info(f"Procesando {len(csv_files)} archivos CSV pendientes")
        
        total_procesados = 0
        for csv_file in csv_files:
            csv_path = os.path.join(csv_dir, csv_file)
            try:
                registros = procesar_archivo_csv(csv_path)
                total_procesados += registros
            except Exception as e:
                logger.error(f"Error procesando {csv_file}: {e}")
        
        logger.info(f"Procesamiento completado: {total_procesados} registros totales")
        return total_procesados
        
    except Exception as e:
        logger.error(f"Error en procesamiento de CSVs pendientes: {e}")


@shared_task
def actualizar_estadisticas_trafico():
    """
    Actualiza estadísticas agregadas de tráfico
    """
    try:
        from django.db.models import Count, Sum
        
        now = timezone.now()
        current_date = now.date()
        current_hour = now.hour
        
        # Obtener o crear estadísticas para la hora actual
        stats, created = TrafficStatistics.objects.get_or_create(
            date=current_date,
            hour=current_hour,
            defaults={
                'total_packets': 0,
                'total_bytes': 0,
                'unique_flows': 0,
            }
        )
        
        # Calcular estadísticas de la última hora
        hour_start = now.replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        
        traffic_hour = TraficoRed.objects.filter(
            fecha_captura__range=[hour_start, hour_end]
        )
        
        # Actualizar contadores
        stats.total_packets = traffic_hour.count()
        stats.total_bytes = traffic_hour.aggregate(
            total=Sum('packet_size')
        )['total'] or 0
        
        # Contadores por protocolo
        protocol_counts = traffic_hour.values('protocol').annotate(
            count=Count('id')
        )
        
        stats.tcp_packets = next((p['count'] for p in protocol_counts if p['protocol'] == 'TCP'), 0)
        stats.udp_packets = next((p['count'] for p in protocol_counts if p['protocol'] == 'UDP'), 0)
        stats.icmp_packets = next((p['count'] for p in protocol_counts if p['protocol'] == 'ICMP'), 0)
        stats.other_packets = stats.total_packets - stats.tcp_packets - stats.udp_packets - stats.icmp_packets
        
        # Contadores por etiqueta
        label_counts = traffic_hour.values('label').annotate(
            count=Count('id')
        )
        
        stats.normal_packets = next((l['count'] for l in label_counts if l['label'] == 'NORMAL'), 0)
        stats.anomalous_packets = next((l['count'] for l in label_counts if l['label'] == 'ANOMALO'), 0)
        stats.suspicious_packets = next((l['count'] for l in label_counts if l['label'] == 'SOSPECHOSO'), 0)
        
        # Calcular flujos únicos
        stats.unique_flows = traffic_hour.values(
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'
        ).distinct().count()
        
        stats.save()
        
        logger.info(f"Estadísticas actualizadas para {current_date} {current_hour:02d}:00")
        
    except Exception as e:
        logger.error(f"Error actualizando estadísticas: {e}")


@shared_task
def limpiar_archivos_antiguos():
    """
    Limpia archivos de captura antiguos según configuración de retención
    """
    try:
        config = SystemConfiguration.get_current_config()
        retention_days = config.retention_days
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        # Directorios a limpiar
        capture_dir = settings.CAPTURE_SETTINGS['CAPTURE_DIR']
        csv_dir = settings.CAPTURE_SETTINGS['CSV_DIR']
        processed_dir = os.path.join(csv_dir, 'processed')
        
        archivos_eliminados = 0
        
        # Limpiar archivos PCAP antiguos
        if os.path.exists(capture_dir):
            for filename in os.listdir(capture_dir):
                filepath = os.path.join(capture_dir, filename)
                if os.path.isfile(filepath):
                    file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if file_time < cutoff_date.replace(tzinfo=None):
                        os.remove(filepath)
                        archivos_eliminados += 1
        
        # Limpiar archivos CSV procesados antiguos
        if os.path.exists(processed_dir):
            for filename in os.listdir(processed_dir):
                filepath = os.path.join(processed_dir, filename)
                if os.path.isfile(filepath):
                    file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if file_time < cutoff_date.replace(tzinfo=None):
                        os.remove(filepath)
                        archivos_eliminados += 1
        
        logger.info(f"Limpieza completada: {archivos_eliminados} archivos eliminados")
        return archivos_eliminados
        
    except Exception as e:
        logger.error(f"Error en limpieza de archivos: {e}")


@shared_task
def generar_reporte_trafico_diario():
    """
    Genera reporte diario de tráfico
    """
    try:
        yesterday = timezone.now().date() - timedelta(days=1)
        
        # Estadísticas del día anterior
        traffic_day = TraficoRed.objects.filter(
            fecha_captura__date=yesterday
        )
        
        total_traffic = traffic_day.count()
        anomalous_traffic = traffic_day.filter(label='ANOMALO').count()
        
        # Solo generar reporte si hay tráfico
        if total_traffic == 0:
            logger.info(f"No hay tráfico para {yesterday}, omitiendo reporte")
            return
        
        anomaly_percentage = (anomalous_traffic / total_traffic) * 100 if total_traffic > 0 else 0
        
        # Generar alerta si hay muchas anomalías
        if anomaly_percentage > 10:  # Más del 10% de anomalías
            create_system_alert(
                title=f'Alto porcentaje de anomalías - {yesterday}',
                description=f'Se detectó {anomaly_percentage:.1f}% de tráfico anómalo el {yesterday}',
                severity='medium',
                alert_type='daily_report',
                alert_data={
                    'date': yesterday.isoformat(),
                    'total_traffic': total_traffic,
                    'anomalous_traffic': anomalous_traffic,
                    'anomaly_percentage': anomaly_percentage
                }
            )
        
        logger.info(f"Reporte diario generado para {yesterday}: {total_traffic} registros, {anomaly_percentage:.1f}% anomalías")
        
    except Exception as e:
        logger.error(f"Error generando reporte diario: {e}")