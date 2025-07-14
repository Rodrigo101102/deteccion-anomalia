"""
Vistas para el procesamiento de predicciones.
"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from apps.traffic.models import TraficoRed


@login_required
def prediction_status(request):
    """
    Muestra el estado de las predicciones.
    """
    pending_count = TraficoRed.objects.filter(label='PENDIENTE').count()
    processed_count = TraficoRed.objects.exclude(label='PENDIENTE').count()
    
    context = {
        'pending_count': pending_count,
        'processed_count': processed_count,
    }
    
    return render(request, 'prediction/status.html', context)


@csrf_exempt
@login_required
def process_traffic(request):
    """
    Procesa el tráfico pendiente para generar predicciones.
    """
    if request.method == 'POST':
        # Aquí se implementaría la lógica de procesamiento
        # Por ahora simulamos el procesamiento
        pending_traffic = TraficoRed.objects.filter(label='PENDIENTE')[:10]
        
        for traffic in pending_traffic:
            # Simulación de predicción (en la implementación real sería ML)
            if traffic.packet_size > 1500 or traffic.duration > 10:
                traffic.label = 'ANOMALO'
                traffic.confidence_score = 0.85
            else:
                traffic.label = 'NORMAL'
                traffic.confidence_score = 0.92
            
            traffic.procesado = True
            traffic.save()
        
        return JsonResponse({
            'status': 'success',
            'message': f'Se procesaron {len(pending_traffic)} registros',
            'processed_count': len(pending_traffic)
        })
    
    return JsonResponse({'status': 'error', 'message': 'Método no permitido'})