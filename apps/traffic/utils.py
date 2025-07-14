"""
Utilidades para la aplicación traffic.
"""

import os
import hashlib
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Sum, Avg, Q
import ipaddress

from .models import TraficoRed, CaptureSession, TrafficStatistics

logger = logging.getLogger(__name__)


def generar_session_id():
    """Genera un ID único para sesión de captura"""
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    random_str = hashlib.md5(str(timezone.now().timestamp()).encode()).hexdigest()[:8]
    return f"capture_{timestamp}_{random_str}"


def validar_interfaz_red(interface):
    """Valida que la interfaz de red existe"""
    try:
        import subprocess
        result = subprocess.run(['ip', 'link', 'show', interface], 
                              capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False


def obtener_interfaces_disponibles():
    """Obtiene lista de interfaces de red disponibles"""
    try:
        import subprocess
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            return ['eth0']  # Fallback
        
        interfaces = []
        for line in result.stdout.split('\n'):
            if ': ' in line and 'state' in line.lower():
                parts = line.split(': ')
                if len(parts) >= 2:
                    interface_name = parts[1].split('@')[0]
                    if interface_name not in ['lo']:  # Excluir loopback
                        interfaces.append(interface_name)
        
        return interfaces if interfaces else ['eth0']
    
    except Exception as e:
        logger.error(f"Error obteniendo interfaces: {e}")
        return ['eth0']


def calcular_estadisticas_trafico(queryset=None, periodo_horas=24):
    """
    Calcula estadísticas detalladas de tráfico
    """
    if queryset is None:
        end_time = timezone.now()
        start_time = end_time - timedelta(hours=periodo_horas)
        queryset = TraficoRed.objects.filter(
            fecha_captura__range=[start_time, end_time]
        )
    
    stats = {
        'resumen': {
            'total_registros': queryset.count(),
            'anomalias': queryset.filter(label='ANOMALO').count(),
            'normales': queryset.filter(label='NORMAL').count(),
            'sin_procesar': queryset.filter(procesado=False).count(),
        },
        'protocolos': list(
            queryset.values('protocol').annotate(
                count=Count('id'),
                avg_packet_size=Avg('packet_size'),
                total_bytes=Sum('packet_size')
            ).order_by('-count')
        ),
        'puertos_destino': list(
            queryset.values('dst_port').annotate(
                count=Count('id')
            ).order_by('-count')[:20]
        ),
        'ips_origen': list(
            queryset.values('src_ip').annotate(
                count=Count('id'),
                anomalias=Count('id', filter=Q(label='ANOMALO'))
            ).order_by('-count')[:20]
        ),
        'ips_destino': list(
            queryset.values('dst_ip').annotate(
                count=Count('id'),
                anomalias=Count('id', filter=Q(label='ANOMALO'))
            ).order_by('-count')[:20]
        ),
        'estadisticas_flujo': {
            'avg_duration': queryset.aggregate(avg=Avg('duration'))['avg'] or 0,
            'avg_packet_size': queryset.aggregate(avg=Avg('packet_size'))['avg'] or 0,
            'avg_bytes_per_sec': queryset.aggregate(avg=Avg('flow_bytes_per_sec'))['avg'] or 0,
            'avg_packets_per_sec': queryset.aggregate(avg=Avg('flow_packets_per_sec'))['avg'] or 0,
        }
    }
    
    # Calcular porcentaje de anomalías
    total = stats['resumen']['total_registros']
    if total > 0:
        stats['resumen']['porcentaje_anomalias'] = (
            stats['resumen']['anomalias'] / total * 100
        )
    else:
        stats['resumen']['porcentaje_anomalias'] = 0
    
    return stats


def analizar_patron_trafico(ip_address, tiempo_ventana_horas=24):
    """
    Analiza patrones de tráfico para una IP específica
    """
    end_time = timezone.now()
    start_time = end_time - timedelta(hours=tiempo_ventana_horas)
    
    # Tráfico origen
    trafico_origen = TraficoRed.objects.filter(
        src_ip=ip_address,
        fecha_captura__range=[start_time, end_time]
    )
    
    # Tráfico destino
    trafico_destino = TraficoRed.objects.filter(
        dst_ip=ip_address,
        fecha_captura__range=[start_time, end_time]
    )
    
    analisis = {
        'ip': ip_address,
        'periodo': {
            'inicio': start_time,
            'fin': end_time,
            'horas': tiempo_ventana_horas
        },
        'como_origen': {
            'total_conexiones': trafico_origen.count(),
            'anomalias': trafico_origen.filter(label='ANOMALO').count(),
            'destinos_unicos': trafico_origen.values('dst_ip').distinct().count(),
            'puertos_destino': list(
                trafico_origen.values('dst_port').annotate(
                    count=Count('id')
                ).order_by('-count')[:10]
            ),
            'protocolos': list(
                trafico_origen.values('protocol').annotate(
                    count=Count('id')
                ).order_by('-count')
            ),
            'total_bytes': trafico_origen.aggregate(
                total=Sum('packet_size')
            )['total'] or 0,
        },
        'como_destino': {
            'total_conexiones': trafico_destino.count(),
            'anomalias': trafico_destino.filter(label='ANOMALO').count(),
            'origenes_unicos': trafico_destino.values('src_ip').distinct().count(),
            'puertos_servicio': list(
                trafico_destino.values('dst_port').annotate(
                    count=Count('id')
                ).order_by('-count')[:10]
            ),
            'protocolos': list(
                trafico_destino.values('protocol').annotate(
                    count=Count('id')
                ).order_by('-count')
            ),
            'total_bytes': trafico_destino.aggregate(
                total=Sum('packet_size')
            )['total'] or 0,
        }
    }
    
    # Calcular métricas de riesgo
    total_trafico = analisis['como_origen']['total_conexiones'] + analisis['como_destino']['total_conexiones']
    total_anomalias = analisis['como_origen']['anomalias'] + analisis['como_destino']['anomalias']
    
    if total_trafico > 0:
        analisis['metricas_riesgo'] = {
            'porcentaje_anomalias': (total_anomalias / total_trafico) * 100,
            'volumen_total': analisis['como_origen']['total_bytes'] + analisis['como_destino']['total_bytes'],
            'diversidad_destinos': analisis['como_origen']['destinos_unicos'],
            'diversidad_origenes': analisis['como_destino']['origenes_unicos'],
            'nivel_riesgo': calcular_nivel_riesgo(total_anomalias, total_trafico)
        }
    else:
        analisis['metricas_riesgo'] = {
            'porcentaje_anomalias': 0,
            'volumen_total': 0,
            'diversidad_destinos': 0,
            'diversidad_origenes': 0,
            'nivel_riesgo': 'BAJO'
        }
    
    return analisis


def calcular_nivel_riesgo(anomalias, total_trafico):
    """Calcula el nivel de riesgo basado en anomalías y volumen"""
    if total_trafico == 0:
        return 'BAJO'
    
    porcentaje_anomalias = (anomalias / total_trafico) * 100
    
    if porcentaje_anomalias >= 50:
        return 'CRITICO'
    elif porcentaje_anomalias >= 20:
        return 'ALTO'
    elif porcentaje_anomalias >= 5:
        return 'MEDIO'
    else:
        return 'BAJO'


def detectar_anomalias_basicas(trafico_registro):
    """
    Detecta anomalías básicas sin ML
    """
    anomalias = []
    
    # Puerto inusual
    puertos_comunes = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
    if trafico_registro.dst_port not in puertos_comunes and trafico_registro.dst_port > 1024:
        anomalias.append('puerto_inusual')
    
    # Duración muy larga
    if trafico_registro.duration > 300:  # Más de 5 minutos
        anomalias.append('duracion_larga')
    
    # Tamaño de paquete inusual
    if trafico_registro.packet_size > 1500:  # Más que MTU estándar
        anomalias.append('paquete_grande')
    elif trafico_registro.packet_size < 64:  # Paquete muy pequeño
        anomalias.append('paquete_pequeno')
    
    # Flujo de datos muy alto
    if trafico_registro.flow_bytes_per_sec > 10000000:  # 10 MB/s
        anomalias.append('flujo_alto')
    
    # Conexión externa sospechosa
    try:
        src_ip = ipaddress.ip_address(trafico_registro.src_ip)
        dst_ip = ipaddress.ip_address(trafico_registro.dst_ip)
        
        # Conexión desde IP externa a puerto interno inusual
        if not src_ip.is_private and dst_ip.is_private and trafico_registro.dst_port > 1024:
            anomalias.append('conexion_externa_sospechosa')
    except:
        pass
    
    return anomalias


def generar_hash_flujo(src_ip, dst_ip, src_port, dst_port, protocol):
    """Genera hash único para un flujo de red"""
    flow_str = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    return hashlib.md5(flow_str.encode()).hexdigest()


def es_ip_privada(ip_str):
    """Verifica si una IP es privada"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False


def es_ip_valida(ip_str):
    """Verifica si una IP es válida"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except:
        return False


def formatear_bytes(bytes_value):
    """Formatea bytes en unidades legibles"""
    if bytes_value == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    
    while bytes_value >= 1024 and unit_index < len(units) - 1:
        bytes_value /= 1024
        unit_index += 1
    
    return f"{bytes_value:.2f} {units[unit_index]}"


def obtener_estadisticas_tiempo_real():
    """Obtiene estadísticas de tráfico en tiempo real"""
    now = timezone.now()
    
    # Últimos 5 minutos
    last_5min = now - timedelta(minutes=5)
    recent_traffic = TraficoRed.objects.filter(fecha_captura__gte=last_5min)
    
    # Última hora
    last_hour = now - timedelta(hours=1)
    hourly_traffic = TraficoRed.objects.filter(fecha_captura__gte=last_hour)
    
    # Sesión de captura activa
    active_session = CaptureSession.objects.filter(status='RUNNING').first()
    
    stats = {
        'timestamp': now.isoformat(),
        'ultimos_5min': {
            'total': recent_traffic.count(),
            'anomalias': recent_traffic.filter(label='ANOMALO').count(),
            'bytes_total': recent_traffic.aggregate(total=Sum('packet_size'))['total'] or 0,
        },
        'ultima_hora': {
            'total': hourly_traffic.count(),
            'anomalias': hourly_traffic.filter(label='ANOMALO').count(),
            'bytes_total': hourly_traffic.aggregate(total=Sum('packet_size'))['total'] or 0,
        },
        'captura_activa': None
    }
    
    if active_session:
        stats['captura_activa'] = {
            'session_id': active_session.session_id,
            'interface': active_session.interface,
            'duracion_planificada': active_session.duration,
            'tiempo_transcurrido': (
                (now - active_session.started_at).total_seconds() 
                if active_session.started_at else 0
            ),
            'estado': active_session.status
        }
    
    return stats


def validar_datos_trafico(data):
    """Valida datos de tráfico antes de insertar"""
    errores = []
    
    # Validar IPs
    if not es_ip_valida(data.get('src_ip', '')):
        errores.append('IP origen inválida')
    
    if not es_ip_valida(data.get('dst_ip', '')):
        errores.append('IP destino inválida')
    
    # Validar puertos
    src_port = data.get('src_port', 0)
    dst_port = data.get('dst_port', 0)
    
    if not 0 <= src_port <= 65535:
        errores.append('Puerto origen fuera de rango (0-65535)')
    
    if not 0 <= dst_port <= 65535:
        errores.append('Puerto destino fuera de rango (0-65535)')
    
    # Validar protocolo
    protocolos_validos = [choice[0] for choice in TraficoRed.PROTOCOL_CHOICES]
    if data.get('protocol', '') not in protocolos_validos:
        errores.append(f'Protocolo inválido. Válidos: {protocolos_validos}')
    
    # Validar valores numéricos
    campos_numericos = [
        ('packet_size', 'Tamaño de paquete'),
        ('duration', 'Duración'),
        ('flow_bytes_per_sec', 'Bytes por segundo'),
        ('flow_packets_per_sec', 'Paquetes por segundo'),
    ]
    
    for campo, nombre in campos_numericos:
        valor = data.get(campo, 0)
        if valor < 0:
            errores.append(f'{nombre} no puede ser negativo')
    
    return errores


def obtener_top_ips_anomalas(limite=10, dias=7):
    """Obtiene las IPs con más anomalías"""
    end_date = timezone.now()
    start_date = end_date - timedelta(days=dias)
    
    # IPs origen con más anomalías
    top_src_ips = TraficoRed.objects.filter(
        fecha_captura__range=[start_date, end_date],
        label='ANOMALO'
    ).values('src_ip').annotate(
        anomalias=Count('id'),
        total_trafico=Count('id', filter=Q(label__isnull=False))
    ).order_by('-anomalias')[:limite]
    
    # IPs destino con más anomalías
    top_dst_ips = TraficoRed.objects.filter(
        fecha_captura__range=[start_date, end_date],
        label='ANOMALO'
    ).values('dst_ip').annotate(
        anomalias=Count('id'),
        total_trafico=Count('id', filter=Q(label__isnull=False))
    ).order_by('-anomalias')[:limite]
    
    return {
        'periodo_dias': dias,
        'top_ips_origen': list(top_src_ips),
        'top_ips_destino': list(top_dst_ips)
    }


def limpiar_registros_antiguos(dias_retencion=30):
    """Limpia registros de tráfico antiguos"""
    cutoff_date = timezone.now() - timedelta(days=dias_retencion)
    
    # Solo eliminar tráfico normal antiguo, mantener anomalías por más tiempo
    registros_eliminados = TraficoRed.objects.filter(
        fecha_captura__lt=cutoff_date,
        label='NORMAL'
    ).delete()
    
    logger.info(f"Limpieza completada: {registros_eliminados[0]} registros eliminados")
    return registros_eliminados[0]


def iniciar_captura_web(interface='eth0', duration=300, user=None):
    """
    Inicia captura de tráfico desde la interfaz web
    Wrapper para el script de captura
    """
    try:
        # Importar aquí para evitar dependencias circulares
        import sys
        import os
        from pathlib import Path
        
        # Añadir scripts al path
        scripts_path = str(Path(__file__).parent.parent.parent / 'scripts')
        if scripts_path not in sys.path:
            sys.path.append(scripts_path)
        
        from scripts.captura_wireshark import CapturaTrafico
        
        # Verificar si ya hay una captura activa
        active_session = CaptureSession.objects.filter(status='RUNNING').first()
        if active_session:
            return {
                'success': False,
                'error': 'Ya hay una captura en curso',
                'session_id': active_session.session_id
            }
        
        # Crear instancia de captura
        captura = CapturaTrafico(interface=interface, duration=duration)
        
        # Crear sesión en BD
        session_id = generar_session_id()
        capture_session = CaptureSession.objects.create(
            session_id=session_id,
            interface=interface,
            duration=duration,
            started_by=user,
            status='PENDING'
        )
        
        # Iniciar captura en segundo plano (simulación)
        # En producción esto debería usar Celery o threading
        import threading
        
        def ejecutar_captura():
            try:
                capture_session.start_capture()
                resultado = captura.capturar_trafico()
                if resultado:
                    capture_session.complete_capture()
                else:
                    capture_session.fail_capture("Error en captura")
            except Exception as e:
                capture_session.fail_capture(str(e))
        
        # Ejecutar en hilo separado para no bloquear la web
        thread = threading.Thread(target=ejecutar_captura)
        thread.daemon = True
        thread.start()
        
        return {
            'success': True,
            'session_id': session_id,
            'message': 'Captura iniciada exitosamente'
        }
        
    except Exception as e:
        logger.error(f"Error iniciando captura web: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def procesar_csv_web(csv_file_path=None):
    """
    Procesa archivos CSV desde la interfaz web
    Wrapper para el script de procesamiento
    """
    try:
        import sys
        from pathlib import Path
        
        # Añadir scripts al path
        scripts_path = str(Path(__file__).parent.parent.parent / 'scripts')
        if scripts_path not in sys.path:
            sys.path.append(scripts_path)
        
        from scripts.procesar_csv import ProcesadorCSV
        
        # Crear procesador
        procesador = ProcesadorCSV()
        
        if csv_file_path:
            # Procesar archivo específico
            registros = procesador.procesar_archivo_csv(os.path.basename(csv_file_path))
            resultado = {
                'procesados': 1 if registros > 0 else 0,
                'registros_totales': registros,
                'errores': 0 if registros > 0 else 1,
                'archivo': csv_file_path
            }
        else:
            # Procesar todos los archivos pendientes
            resultado = procesador.procesar_todos_csv()
        
        return {
            'success': True,
            'resultado': resultado,
            'message': f"Procesamiento completado: {resultado['registros_totales']} registros"
        }
        
    except Exception as e:
        logger.error(f"Error procesando CSV web: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def ejecutar_predicciones_web(registros_ids=None, batch_size=1000):
    """
    Ejecuta predicciones ML desde la interfaz web
    Wrapper para el script de predicción
    """
    try:
        import sys
        from pathlib import Path
        
        # Añadir scripts al path
        scripts_path = str(Path(__file__).parent.parent.parent / 'scripts')
        if scripts_path not in sys.path:
            sys.path.append(scripts_path)
        
        from scripts.predecir_csv import PredictorAnomalias
        
        # Crear predictor
        predictor = PredictorAnomalias()
        
        # Verificar que el modelo esté disponible
        if not predictor.validar_modelo():
            return {
                'success': False,
                'error': 'Modelo ML no disponible. Entrenar modelo primero.'
            }
        
        # Ejecutar predicciones
        registros_procesados = predictor.predecir_anomalias(
            registros_ids=registros_ids,
            batch_size=batch_size
        )
        
        return {
            'success': True,
            'registros_procesados': registros_procesados,
            'message': f"Predicciones completadas: {registros_procesados} registros procesados"
        }
        
    except Exception as e:
        logger.error(f"Error ejecutando predicciones web: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def entrenar_modelo_web():
    """
    Entrena nuevo modelo ML desde la interfaz web
    """
    try:
        import sys
        from pathlib import Path
        
        # Añadir scripts al path
        scripts_path = str(Path(__file__).parent.parent.parent / 'scripts')
        if scripts_path not in sys.path:
            sys.path.append(scripts_path)
        
        from scripts.predecir_csv import PredictorAnomalias
        
        # Crear predictor
        predictor = PredictorAnomalias()
        
        # Entrenar modelo
        exito = predictor.entrenar_modelo_inicial()
        
        if exito:
            return {
                'success': True,
                'message': 'Modelo entrenado exitosamente'
            }
        else:
            return {
                'success': False,
                'error': 'Error entrenando modelo'
            }
        
    except Exception as e:
        logger.error(f"Error entrenando modelo web: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def obtener_estado_pipeline():
    """
    Obtiene el estado actual del pipeline completo
    """
    try:
        # Estado de capturas
        capturas_activas = CaptureSession.objects.filter(status='RUNNING').count()
        capturas_completadas = CaptureSession.objects.filter(status='COMPLETED').count()
        capturas_fallidas = CaptureSession.objects.filter(status='FAILED').count()
        
        # Estado de procesamiento
        registros_sin_procesar = TraficoRed.objects.filter(procesado=False).count()
        registros_procesados = TraficoRed.objects.filter(procesado=True).count()
        
        # Estado de predicciones
        anomalias_detectadas = TraficoRed.objects.filter(label='ANOMALO').count()
        registros_normales = TraficoRed.objects.filter(label='NORMAL').count()
        
        # Archivos CSV pendientes
        csv_dir = '/media/csv_files/'
        archivos_csv_pendientes = 0
        if os.path.exists(csv_dir):
            archivos_csv_pendientes = len([
                f for f in os.listdir(csv_dir) 
                if f.endswith('.csv') and os.path.isfile(os.path.join(csv_dir, f))
            ])
        
        return {
            'captura': {
                'activas': capturas_activas,
                'completadas': capturas_completadas,
                'fallidas': capturas_fallidas,
                'estado': 'ACTIVA' if capturas_activas > 0 else 'INACTIVA'
            },
            'procesamiento': {
                'sin_procesar': registros_sin_procesar,
                'procesados': registros_procesados,
                'archivos_csv_pendientes': archivos_csv_pendientes,
                'estado': 'PENDIENTE' if archivos_csv_pendientes > 0 or registros_sin_procesar > 0 else 'COMPLETADO'
            },
            'prediccion': {
                'anomalias': anomalias_detectadas,
                'normales': registros_normales,
                'total_clasificados': anomalias_detectadas + registros_normales,
                'porcentaje_anomalias': (
                    (anomalias_detectadas / (anomalias_detectadas + registros_normales) * 100)
                    if (anomalias_detectadas + registros_normales) > 0 else 0
                )
            }
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estado del pipeline: {e}")
        return {
            'error': str(e)
        }