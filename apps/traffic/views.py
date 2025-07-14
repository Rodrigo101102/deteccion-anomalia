"""
Vistas para el manejo de tráfico de red.
"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from .models import TraficoRed, CaptureSession
import json


@login_required
def traffic_list(request):
    """
    Lista paginada del tráfico de red.
    """
    traffic_data = TraficoRed.objects.all()
    
    # Filtros
    protocol_filter = request.GET.get('protocol')
    label_filter = request.GET.get('label')
    date_filter = request.GET.get('date')
    
    if protocol_filter:
        traffic_data = traffic_data.filter(protocol=protocol_filter)
    if label_filter:
        traffic_data = traffic_data.filter(label=label_filter)
    if date_filter:
        traffic_data = traffic_data.filter(fecha_captura__date=date_filter)
    
    # Paginación
    paginator = Paginator(traffic_data, 20)  # 20 resultados por página
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'protocols': TraficoRed.PROTOCOL_CHOICES,
        'labels': TraficoRed.LABEL_CHOICES,
        'current_filters': {
            'protocol': protocol_filter,
            'label': label_filter,
            'date': date_filter,
        }
    }
    
    return render(request, 'traffic/list.html', context)


@csrf_exempt
@login_required
def start_capture(request):
    """
    Inicia una nueva sesión de captura de tráfico.
    """
    if request.method == 'POST':
        # Aquí se implementaría la lógica para iniciar la captura
        # Por ahora devolvemos una respuesta simulada
        return JsonResponse({
            'status': 'success',
            'message': 'Captura iniciada exitosamente',
            'session_id': 'capture_session_123'
        })
    
    return JsonResponse({'status': 'error', 'message': 'Método no permitido'})


@csrf_exempt
@login_required
def stop_capture(request):
    """
    Detiene la sesión de captura actual.
    """
    if request.method == 'POST':
        # Aquí se implementaría la lógica para detener la captura
        return JsonResponse({
            'status': 'success',
            'message': 'Captura detenida exitosamente'
        })
    
    return JsonResponse({'status': 'error', 'message': 'Método no permitido'})


@login_required
def capture_status(request):
    """
    Obtiene el estado actual de las capturas.
    """
    active_sessions = CaptureSession.objects.filter(
        status__in=['CAPTURING', 'PROCESSING']
    ).count()
    
    return JsonResponse({
        'active_sessions': active_sessions,
        'status': 'active' if active_sessions > 0 else 'inactive'
    })