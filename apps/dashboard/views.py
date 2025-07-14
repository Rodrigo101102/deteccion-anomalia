from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView
from django.http import JsonResponse
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from apps.traffic.models import TraficoRed
from apps.prediction.models import ModeloPrediccion
from apps.core.models import SystemAlert


@method_decorator(login_required, name='dispatch')
class DashboardHomeView(TemplateView):
    template_name = 'dashboard/index.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Estadísticas generales
        context['total_traffic'] = TraficoRed.objects.count()
        context['anomalies_today'] = TraficoRed.objects.filter(
            label='ANOMALO',
            fecha_captura__date=timezone.now().date()
        ).count()
        context['normal_traffic'] = TraficoRed.objects.filter(label='NORMAL').count()
        context['unprocessed_traffic'] = TraficoRed.objects.filter(procesado=False).count()
        
        # Alertas activas
        context['active_alerts'] = SystemAlert.objects.filter(is_resolved=False).count()
        
        return context


@method_decorator(login_required, name='dispatch')
class TrafficListView(TemplateView):
    template_name = 'dashboard/traffic_list.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Filtros
        label_filter = self.request.GET.get('label', 'all')
        date_filter = self.request.GET.get('date', 'today')
        
        # Query base
        queryset = TraficoRed.objects.all()
        
        # Aplicar filtros
        if label_filter != 'all':
            queryset = queryset.filter(label=label_filter)
        
        if date_filter == 'today':
            queryset = queryset.filter(fecha_captura__date=timezone.now().date())
        elif date_filter == 'week':
            week_ago = timezone.now() - timedelta(days=7)
            queryset = queryset.filter(fecha_captura__gte=week_ago)
        
        # Paginación
        from django.core.paginator import Paginator
        paginator = Paginator(queryset.order_by('-fecha_captura'), 20)
        page_number = self.request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        context['traffic_data'] = page_obj
        context['current_filters'] = {
            'label': label_filter,
            'date': date_filter
        }
        
        return context


@method_decorator(login_required, name='dispatch')
class AlertsView(TemplateView):
    template_name = 'dashboard/alerts.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Alertas recientes
        context['recent_alerts'] = SystemAlert.objects.order_by('-created_at')[:10]
        context['unresolved_alerts'] = SystemAlert.objects.filter(is_resolved=False)
        
        return context


@method_decorator(login_required, name='dispatch')
class StatisticsView(TemplateView):
    template_name = 'dashboard/statistics.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Estadísticas por día (últimos 7 días)
        today = timezone.now().date()
        stats_by_day = []
        
        for i in range(7):
            date = today - timedelta(days=i)
            total = TraficoRed.objects.filter(fecha_captura__date=date).count()
            anomalies = TraficoRed.objects.filter(
                fecha_captura__date=date,
                label='ANOMALO'
            ).count()
            
            stats_by_day.append({
                'date': date.strftime('%Y-%m-%d'),
                'total': total,
                'anomalies': anomalies,
                'normal': total - anomalies
            })
        
        context['stats_by_day'] = list(reversed(stats_by_day))
        
        # Estadísticas por protocolo
        protocol_stats = (TraficoRed.objects
                         .values('protocol')
                         .annotate(count=Count('id'))
                         .order_by('-count')[:10])
        
        context['protocol_stats'] = protocol_stats
        
        return context


@login_required
def api_traffic_stats(request):
    """API endpoint para estadísticas de tráfico en tiempo real"""
    
    # Estadísticas de los últimos 30 minutos
    thirty_min_ago = timezone.now() - timedelta(minutes=30)
    
    recent_traffic = TraficoRed.objects.filter(fecha_captura__gte=thirty_min_ago)
    
    stats = {
        'total_recent': recent_traffic.count(),
        'anomalies_recent': recent_traffic.filter(label='ANOMALO').count(),
        'normal_recent': recent_traffic.filter(label='NORMAL').count(),
        'unprocessed_recent': recent_traffic.filter(procesado=False).count(),
        'timestamp': timezone.now().isoformat()
    }
    
    return JsonResponse(stats)


@login_required
def api_protocol_distribution(request):
    """API endpoint para distribución de protocolos"""
    
    protocol_data = (TraficoRed.objects
                     .values('protocol')
                     .annotate(count=Count('id'))
                     .order_by('-count')[:10])
    
    data = {
        'labels': [item['protocol'] for item in protocol_data],
        'data': [item['count'] for item in protocol_data]
    }
    
    return JsonResponse(data)


@login_required
def api_anomaly_trend(request):
    """API endpoint para tendencia de anomalías"""
    
    # Últimas 24 horas, agrupado por hora
    now = timezone.now()
    hours_data = []
    
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        
        total = TraficoRed.objects.filter(
            fecha_captura__gte=hour_start,
            fecha_captura__lt=hour_end
        ).count()
        
        anomalies = TraficoRed.objects.filter(
            fecha_captura__gte=hour_start,
            fecha_captura__lt=hour_end,
            label='ANOMALO'
        ).count()
        
        hours_data.append({
            'hour': hour_start.strftime('%H:%M'),
            'total': total,
            'anomalies': anomalies
        })
    
    data = {
        'labels': [item['hour'] for item in reversed(hours_data)],
        'total': [item['total'] for item in reversed(hours_data)],
        'anomalies': [item['anomalies'] for item in reversed(hours_data)]
    }
    
    return JsonResponse(data)