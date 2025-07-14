"""
Vistas para la gestión de tráfico de red.
"""

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django.db.models import Q, Count, Sum, Avg
from django.utils import timezone
from datetime import datetime, timedelta
from django.conf import settings
import json

from .models import TraficoRed, CaptureSession, TrafficStatistics
from .serializers import TraficoRedSerializer, CaptureSessionSerializer
from .filters import TrafficFilter
from .tasks import iniciar_captura_trafico, procesar_csv_pendientes
from apps.core.decorators import analyst_required, operator_required
from apps.core.utils import log_user_action, export_data_to_csv


class TrafficListView(LoginRequiredMixin, ListView):
    """Vista para listar tráfico de red"""
    model = TraficoRed
    template_name = 'traffic/traffic_list.html'
    context_object_name = 'traffic_data'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = TraficoRed.objects.all().order_by('-fecha_captura')
        
        # Aplicar filtros
        traffic_filter = TrafficFilter(self.request.GET, queryset=queryset)
        return traffic_filter.qs
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Añadir filtro al contexto
        context['filter'] = TrafficFilter(self.request.GET, queryset=self.get_queryset())
        
        # Estadísticas rápidas
        queryset = self.get_queryset()
        context['stats'] = {
            'total': queryset.count(),
            'anomalous': queryset.filter(label='ANOMALO').count(),
            'normal': queryset.filter(label='NORMAL').count(),
            'unprocessed': queryset.filter(procesado=False).count(),
        }
        
        return context


class TrafficDetailView(LoginRequiredMixin, DetailView):
    """Vista detallada de tráfico"""
    model = TraficoRed
    template_name = 'traffic/traffic_detail.html'
    context_object_name = 'traffic'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Tráfico relacionado (mismo flujo)
        traffic = self.get_object()
        related_traffic = TraficoRed.objects.filter(
            Q(src_ip=traffic.src_ip, dst_ip=traffic.dst_ip) |
            Q(src_ip=traffic.dst_ip, dst_ip=traffic.src_ip)
        ).exclude(id=traffic.id).order_by('-fecha_captura')[:10]
        
        context['related_traffic'] = related_traffic
        
        return context


@login_required
def traffic_analytics_view(request):
    """Vista de analítica de tráfico"""
    # Estadísticas de los últimos 7 días
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=7)
    
    # Estadísticas por día
    daily_stats = TrafficStatistics.objects.filter(
        date__range=[start_date, end_date]
    ).values('date').annotate(
        total_packets=Sum('total_packets'),
        anomalous_packets=Sum('anomalous_packets'),
        total_bytes=Sum('total_bytes')
    ).order_by('date')
    
    # Estadísticas por protocolo
    protocol_stats = TraficoRed.objects.filter(
        fecha_captura__date__range=[start_date, end_date]
    ).values('protocol').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Top IPs de origen
    top_src_ips = TraficoRed.objects.filter(
        fecha_captura__date__range=[start_date, end_date]
    ).values('src_ip').annotate(
        count=Count('id'),
        anomalies=Count('id', filter=Q(label='ANOMALO'))
    ).order_by('-count')[:10]
    
    # Top puertos de destino
    top_dst_ports = TraficoRed.objects.filter(
        fecha_captura__date__range=[start_date, end_date]
    ).values('dst_port').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    context = {
        'daily_stats': list(daily_stats),
        'protocol_stats': list(protocol_stats),
        'top_src_ips': list(top_src_ips),
        'top_dst_ports': list(top_dst_ports),
        'start_date': start_date,
        'end_date': end_date,
    }
    
    return render(request, 'traffic/analytics.html', context)


@operator_required
def start_capture_view(request):
    """Vista para iniciar captura de tráfico"""
    if request.method == 'POST':
        try:
            duration = int(request.POST.get('duration', 300))
            interface = request.POST.get('interface', 'eth0')
            
            # Verificar si ya hay una captura en curso
            active_session = CaptureSession.objects.filter(
                status='RUNNING'
            ).first()
            
            if active_session:
                return JsonResponse({
                    'error': 'Ya hay una captura en curso',
                    'session_id': active_session.session_id
                }, status=400)
            
            # Crear nueva sesión de captura
            session_id = f"capture_{timezone.now().strftime('%Y%m%d_%H%M%S')}"
            capture_session = CaptureSession.objects.create(
                session_id=session_id,
                interface=interface,
                duration=duration,
                started_by=request.user
            )
            
            # Iniciar tarea de captura asíncrona
            iniciar_captura_trafico.delay(session_id)
            
            # Log de auditoría
            log_user_action(
                user=request.user,
                action='capture_start',
                description=f'Captura iniciada: {session_id}',
                request=request,
                additional_data={
                    'session_id': session_id,
                    'duration': duration,
                    'interface': interface
                }
            )
            
            return JsonResponse({
                'success': True,
                'session_id': session_id,
                'message': 'Captura iniciada exitosamente'
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@operator_required
def stop_capture_view(request):
    """Vista para detener captura de tráfico"""
    if request.method == 'POST':
        try:
            session_id = request.POST.get('session_id')
            
            if not session_id:
                return JsonResponse({'error': 'ID de sesión requerido'}, status=400)
            
            capture_session = get_object_or_404(CaptureSession, session_id=session_id)
            
            if capture_session.status != 'RUNNING':
                return JsonResponse({
                    'error': 'La captura no está en ejecución'
                }, status=400)
            
            # Cancelar la sesión
            capture_session.status = 'CANCELLED'
            capture_session.completed_at = timezone.now()
            capture_session.save()
            
            # Log de auditoría
            log_user_action(
                user=request.user,
                action='capture_stop',
                description=f'Captura detenida: {session_id}',
                request=request,
                additional_data={'session_id': session_id}
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Captura detenida exitosamente'
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)


class CaptureSessionListView(LoginRequiredMixin, ListView):
    """Vista para listar sesiones de captura"""
    model = CaptureSession
    template_name = 'traffic/capture_sessions.html'
    context_object_name = 'sessions'
    paginate_by = 20
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Estadísticas de sesiones
        context['session_stats'] = {
            'total': CaptureSession.objects.count(),
            'running': CaptureSession.objects.filter(status='RUNNING').count(),
            'completed': CaptureSession.objects.filter(status='COMPLETED').count(),
            'failed': CaptureSession.objects.filter(status='FAILED').count(),
        }
        
        return context


@login_required
def traffic_api_list(request):
    """API REST para listar tráfico"""
    try:
        # Parámetros de paginación
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 20))
        
        # Filtros
        queryset = TraficoRed.objects.all().order_by('-fecha_captura')
        
        label = request.GET.get('label')
        if label:
            queryset = queryset.filter(label=label)
        
        src_ip = request.GET.get('src_ip')
        if src_ip:
            queryset = queryset.filter(src_ip=src_ip)
        
        date_from = request.GET.get('date_from')
        if date_from:
            try:
                date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
                queryset = queryset.filter(fecha_captura__date__gte=date_from)
            except ValueError:
                pass
        
        # Paginación
        paginator = Paginator(queryset, page_size)
        page_obj = paginator.get_page(page)
        
        # Serializar datos
        serializer = TraficoRedSerializer(page_obj.object_list, many=True)
        
        return JsonResponse({
            'results': serializer.data,
            'count': paginator.count,
            'num_pages': paginator.num_pages,
            'current_page': page,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous(),
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def traffic_export_view(request):
    """Vista para exportar datos de tráfico"""
    try:
        # Obtener filtros de la request
        queryset = TraficoRed.objects.all().order_by('-fecha_captura')
        
        # Aplicar filtros similares a la vista de lista
        traffic_filter = TrafficFilter(request.GET, queryset=queryset)
        filtered_queryset = traffic_filter.qs
        
        # Limitar exportación para evitar sobrecarga
        max_records = 10000
        if filtered_queryset.count() > max_records:
            filtered_queryset = filtered_queryset[:max_records]
        
        # Campos a exportar
        fields = [
            'id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'packet_size', 'duration', 'flow_bytes_per_sec', 'flow_packets_per_sec',
            'label', 'confidence_score', 'fecha_captura', 'procesado'
        ]
        
        # Generar CSV
        response = export_data_to_csv(
            queryset=filtered_queryset,
            fields=fields,
            filename=f'traffic_export_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        
        # Log de auditoría
        log_user_action(
            user=request.user,
            action='data_export',
            description=f'Exportación de {filtered_queryset.count()} registros de tráfico',
            request=request,
            additional_data={'record_count': filtered_queryset.count()}
        )
        
        return response
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@analyst_required
def traffic_statistics_api(request):
    """API para estadísticas de tráfico"""
    try:
        # Período de análisis
        days = int(request.GET.get('days', 7))
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days)
        
        # Estadísticas generales
        total_traffic = TraficoRed.objects.filter(
            fecha_captura__date__range=[start_date, end_date]
        )
        
        stats = {
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days
            },
            'totals': {
                'total_records': total_traffic.count(),
                'anomalous_records': total_traffic.filter(label='ANOMALO').count(),
                'normal_records': total_traffic.filter(label='NORMAL').count(),
                'unprocessed_records': total_traffic.filter(procesado=False).count(),
            },
            'by_protocol': list(
                total_traffic.values('protocol').annotate(
                    count=Count('id')
                ).order_by('-count')
            ),
            'by_hour': list(
                total_traffic.extra(
                    select={'hour': 'EXTRACT(hour FROM fecha_captura)'}
                ).values('hour').annotate(
                    count=Count('id'),
                    anomalies=Count('id', filter=Q(label='ANOMALO'))
                ).order_by('hour')
            ),
            'top_sources': list(
                total_traffic.values('src_ip').annotate(
                    count=Count('id'),
                    anomalies=Count('id', filter=Q(label='ANOMALO'))
                ).order_by('-count')[:10]
            ),
            'top_destinations': list(
                total_traffic.values('dst_ip').annotate(
                    count=Count('id')
                ).order_by('-count')[:10]
            )
        }
        
        return JsonResponse(stats)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@operator_required
def process_pending_csv_view(request):
    """Vista para procesar CSVs pendientes manualmente"""
    if request.method == 'POST':
        try:
            # Iniciar procesamiento asíncrono
            task = procesar_csv_pendientes.delay()
            
            # Log de auditoría
            log_user_action(
                user=request.user,
                action='csv_process',
                description='Procesamiento manual de CSVs iniciado',
                request=request,
                additional_data={'task_id': task.id}
            )
            
            return JsonResponse({
                'success': True,
                'task_id': task.id,
                'message': 'Procesamiento de CSVs iniciado'
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@login_required
def traffic_realtime_data(request):
    """API para datos en tiempo real"""
    try:
        # Datos de los últimos 5 minutos
        now = timezone.now()
        five_minutes_ago = now - timedelta(minutes=5)
        
        recent_traffic = TraficoRed.objects.filter(
            fecha_captura__gte=five_minutes_ago
        )
        
        data = {
            'timestamp': now.isoformat(),
            'recent_count': recent_traffic.count(),
            'recent_anomalies': recent_traffic.filter(label='ANOMALO').count(),
            'current_capture': None
        }
        
        # Información de captura actual
        current_capture = CaptureSession.objects.filter(status='RUNNING').first()
        if current_capture:
            data['current_capture'] = {
                'session_id': current_capture.session_id,
                'started_at': current_capture.started_at.isoformat() if current_capture.started_at else None,
                'duration': current_capture.duration,
                'interface': current_capture.interface
            }
        
        return JsonResponse(data)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def traffic_pipeline_view(request):
    """Vista principal del pipeline de tráfico"""
    from .utils import obtener_estado_pipeline, obtener_interfaces_disponibles
    
    context = {
        'estado_pipeline': obtener_estado_pipeline(),
        'interfaces_disponibles': obtener_interfaces_disponibles(),
        'duraciones_captura': [
            (60, '1 minuto'),
            (300, '5 minutos'), 
            (600, '10 minutos'),
            (1800, '30 minutos'),
            (3600, '1 hora')
        ]
    }
    
    return render(request, 'traffic/pipeline.html', context)


@operator_required
def capture_management_view(request):
    """Vista de gestión de capturas"""
    from .utils import obtener_interfaces_disponibles, iniciar_captura_web
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'start_capture':
            interface = request.POST.get('interface', 'eth0')
            duration = int(request.POST.get('duration', 300))
            
            resultado = iniciar_captura_web(
                interface=interface,
                duration=duration,
                user=request.user
            )
            
            if resultado['success']:
                return JsonResponse({
                    'success': True,
                    'message': resultado['message'],
                    'session_id': resultado['session_id']
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': resultado['error']
                }, status=400)
    
    # GET request - mostrar formulario
    context = {
        'interfaces_disponibles': obtener_interfaces_disponibles(),
        'duraciones_captura': [
            (60, '1 minuto'),
            (300, '5 minutos'), 
            (600, '10 minutos'),
            (1800, '30 minutos'),
            (3600, '1 hora')
        ],
        'capturas_recientes': CaptureSession.objects.all()[:10]
    }
    
    return render(request, 'traffic/capture_management.html', context)


@operator_required 
def csv_processing_view(request):
    """Vista de procesamiento de CSV"""
    from .utils import procesar_csv_web
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'process_all':
            resultado = procesar_csv_web()
            
            if resultado['success']:
                return JsonResponse({
                    'success': True,
                    'message': resultado['message'],
                    'resultado': resultado['resultado']
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': resultado['error']
                }, status=400)
        
        elif action == 'process_file':
            archivo = request.POST.get('archivo')
            if archivo:
                resultado = procesar_csv_web(csv_file_path=archivo)
                
                if resultado['success']:
                    return JsonResponse({
                        'success': True,
                        'message': resultado['message'],
                        'resultado': resultado['resultado']
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': resultado['error']
                    }, status=400)
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Archivo no especificado'
                }, status=400)
    
    # GET request - mostrar interfaz
    import os
    csv_dir = '/media/csv_files/'
    archivos_csv = []
    
    if os.path.exists(csv_dir):
        archivos_csv = [
            f for f in os.listdir(csv_dir) 
            if f.endswith('.csv') and os.path.isfile(os.path.join(csv_dir, f))
        ]
    
    context = {
        'archivos_csv': archivos_csv,
        'total_sin_procesar': TraficoRed.objects.filter(procesado=False).count(),
        'total_procesados': TraficoRed.objects.filter(procesado=True).count()
    }
    
    return render(request, 'traffic/csv_processing.html', context)


@analyst_required
def ml_prediction_view(request):
    """Vista de predicciones ML"""
    from .utils import ejecutar_predicciones_web, entrenar_modelo_web
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'predict':
            batch_size = int(request.POST.get('batch_size', 1000))
            
            resultado = ejecutar_predicciones_web(batch_size=batch_size)
            
            if resultado['success']:
                return JsonResponse({
                    'success': True,
                    'message': resultado['message'],
                    'registros_procesados': resultado['registros_procesados']
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': resultado['error']
                }, status=400)
        
        elif action == 'train_model':
            resultado = entrenar_modelo_web()
            
            if resultado['success']:
                return JsonResponse({
                    'success': True,
                    'message': resultado['message']
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': resultado['error']
                }, status=400)
    
    # GET request - mostrar interfaz
    total_sin_procesar = TraficoRed.objects.filter(procesado=False).count()
    total_anomalias = TraficoRed.objects.filter(label='ANOMALO').count()
    total_normales = TraficoRed.objects.filter(label='NORMAL').count()
    total_clasificados = total_anomalias + total_normales
    
    context = {
        'total_sin_procesar': total_sin_procesar,
        'total_anomalias': total_anomalias,
        'total_normales': total_normales,
        'total_clasificados': total_clasificados,
        'porcentaje_anomalias': (
            (total_anomalias / total_clasificados * 100) 
            if total_clasificados > 0 else 0
        ),
        'batch_sizes': [100, 500, 1000, 2000, 5000]
    }
    
    return render(request, 'traffic/ml_prediction.html', context)