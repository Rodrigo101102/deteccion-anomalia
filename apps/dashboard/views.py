"""
Vistas del dashboard administrativo.
"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from apps.traffic.models import TraficoRed, CaptureSession
from apps.core.models import User


def is_admin(user):
    """Verifica si el usuario es administrador."""
    return user.is_authenticated and user.is_admin()


@login_required
@user_passes_test(is_admin)
def index(request):
    """
    Vista principal del dashboard administrativo.
    """
    # Estadísticas generales
    total_traffic = TraficoRed.objects.count()
    anomalous_traffic = TraficoRed.objects.filter(label='ANOMALO').count()
    normal_traffic = TraficoRed.objects.filter(label='NORMAL').count()
    pending_traffic = TraficoRed.objects.filter(label='PENDIENTE').count()
    
    # Estadísticas de las últimas 24 horas
    last_24h = timezone.now() - timedelta(hours=24)
    recent_traffic = TraficoRed.objects.filter(fecha_captura__gte=last_24h)
    recent_anomalies = recent_traffic.filter(label='ANOMALO').count()
    
    # Estadísticas por protocolo
    protocol_stats = TraficoRed.objects.values('protocol').annotate(
        count=Count('id'),
        anomalies=Count('id', filter=Q(label='ANOMALO'))
    ).order_by('-count')
    
    # Sesiones de captura activas
    active_sessions = CaptureSession.objects.filter(
        status__in=['CAPTURING', 'PROCESSING']
    ).count()
    
    # Últimas anomalías detectadas
    latest_anomalies = TraficoRed.objects.filter(
        label='ANOMALO'
    ).order_by('-fecha_captura')[:10]
    
    context = {
        'total_traffic': total_traffic,
        'anomalous_traffic': anomalous_traffic,
        'normal_traffic': normal_traffic,
        'pending_traffic': pending_traffic,
        'recent_anomalies': recent_anomalies,
        'protocol_stats': protocol_stats,
        'active_sessions': active_sessions,
        'latest_anomalies': latest_anomalies,
        'anomaly_percentage': (anomalous_traffic / total_traffic * 100) if total_traffic > 0 else 0,
    }
    
    return render(request, 'dashboard/index.html', context)


@login_required
@user_passes_test(is_admin)
def traffic_analysis(request):
    """
    Vista detallada de análisis de tráfico.
    """
    # Análisis temporal (últimos 7 días)
    end_date = timezone.now()
    start_date = end_date - timedelta(days=7)
    
    daily_stats = []
    for i in range(7):
        day = start_date + timedelta(days=i)
        day_traffic = TraficoRed.objects.filter(
            fecha_captura__date=day.date()
        )
        
        daily_stats.append({
            'date': day.date(),
            'total': day_traffic.count(),
            'anomalies': day_traffic.filter(label='ANOMALO').count(),
            'normal': day_traffic.filter(label='NORMAL').count(),
        })
    
    # Top IPs con más tráfico anómalo
    top_anomalous_ips = TraficoRed.objects.filter(
        label='ANOMALO'
    ).values('src_ip').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    context = {
        'daily_stats': daily_stats,
        'top_anomalous_ips': top_anomalous_ips,
    }
    
    return render(request, 'dashboard/analysis.html', context)


@login_required
@user_passes_test(is_admin)
def system_status(request):
    """
    Vista del estado del sistema.
    """
    # Estados de las sesiones de captura
    capture_sessions = CaptureSession.objects.order_by('-created_at')[:20]
    
    # Usuarios del sistema
    total_users = User.objects.count()
    admin_users = User.objects.filter(role='admin').count()
    
    context = {
        'capture_sessions': capture_sessions,
        'total_users': total_users,
        'admin_users': admin_users,
    }
    
    return render(request, 'dashboard/status.html', context)