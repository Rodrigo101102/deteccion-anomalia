"""
Filtros para la aplicación traffic.
"""

import django_filters
from django import forms
from django.db.models import Q
from datetime import datetime, timedelta
from django.utils import timezone

from .models import TraficoRed, CaptureSession, TrafficStatistics


class TrafficFilter(django_filters.FilterSet):
    """Filtro para el modelo TraficoRed"""
    
    # Filtros de fecha
    fecha_desde = django_filters.DateFilter(
        field_name='fecha_captura',
        lookup_expr='date__gte',
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
    )
    fecha_hasta = django_filters.DateFilter(
        field_name='fecha_captura',
        lookup_expr='date__lte',
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
    )
    
    # Filtros de tiempo predefinidos
    PERIOD_CHOICES = [
        ('', 'Todos los períodos'),
        ('1h', 'Última hora'),
        ('6h', 'Últimas 6 horas'),
        ('24h', 'Últimas 24 horas'),
        ('7d', 'Últimos 7 días'),
        ('30d', 'Últimos 30 días'),
    ]
    
    periodo = django_filters.ChoiceFilter(
        choices=PERIOD_CHOICES,
        method='filter_by_period',
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    # Filtros de red
    src_ip = django_filters.CharFilter(
        field_name='src_ip',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'IP Origen'})
    )
    dst_ip = django_filters.CharFilter(
        field_name='dst_ip',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'IP Destino'})
    )
    
    src_port = django_filters.NumberFilter(
        field_name='src_port',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Puerto Origen'})
    )
    dst_port = django_filters.NumberFilter(
        field_name='dst_port',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Puerto Destino'})
    )
    
    # Filtro de protocolo
    protocol = django_filters.ChoiceFilter(
        choices=TraficoRed.PROTOCOL_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    # Filtro de etiqueta
    label = django_filters.ChoiceFilter(
        choices=[('', 'Todas las etiquetas')] + TraficoRed.LABEL_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    # Filtro de estado de procesamiento
    procesado = django_filters.BooleanFilter(
        widget=forms.Select(
            choices=[('', 'Todos'), (True, 'Procesado'), (False, 'Sin procesar')],
            attrs={'class': 'form-select'}
        )
    )
    
    # Filtros de tamaño de paquete
    packet_size_min = django_filters.NumberFilter(
        field_name='packet_size',
        lookup_expr='gte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Tamaño mín.'})
    )
    packet_size_max = django_filters.NumberFilter(
        field_name='packet_size',
        lookup_expr='lte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Tamaño máx.'})
    )
    
    # Filtro de duración
    duration_min = django_filters.NumberFilter(
        field_name='duration',
        lookup_expr='gte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Duración mín.', 'step': '0.1'})
    )
    duration_max = django_filters.NumberFilter(
        field_name='duration',
        lookup_expr='lte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Duración máx.', 'step': '0.1'})
    )
    
    # Filtro de puntuación de confianza
    confidence_min = django_filters.NumberFilter(
        field_name='confidence_score',
        lookup_expr='gte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Confianza mín.', 'step': '0.01', 'min': '0', 'max': '1'})
    )
    
    # Filtro de dirección de tráfico
    DIRECTION_CHOICES = [
        ('', 'Todas las direcciones'),
        ('internal', 'Interno'),
        ('inbound', 'Entrante'),
        ('outbound', 'Saliente'),
        ('external', 'Externo'),
    ]
    
    direccion = django_filters.ChoiceFilter(
        choices=DIRECTION_CHOICES,
        method='filter_by_direction',
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    # Filtro de archivo origen
    archivo_origen = django_filters.CharFilter(
        field_name='archivo_origen',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Archivo origen'})
    )
    
    # Búsqueda general
    search = django_filters.CharFilter(
        method='general_search',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Buscar en IPs, puertos...'})
    )
    
    class Meta:
        model = TraficoRed
        fields = []
    
    def filter_by_period(self, queryset, name, value):
        """Filtrar por período de tiempo predefinido"""
        if not value:
            return queryset
        
        now = timezone.now()
        
        if value == '1h':
            start_time = now - timedelta(hours=1)
        elif value == '6h':
            start_time = now - timedelta(hours=6)
        elif value == '24h':
            start_time = now - timedelta(hours=24)
        elif value == '7d':
            start_time = now - timedelta(days=7)
        elif value == '30d':
            start_time = now - timedelta(days=30)
        else:
            return queryset
        
        return queryset.filter(fecha_captura__gte=start_time)
    
    def filter_by_direction(self, queryset, name, value):
        """Filtrar por dirección de tráfico"""
        if not value:
            return queryset
        
        import ipaddress
        
        if value == 'internal':
            # Ambas IPs privadas
            private_ranges = [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16'
            ]
            q = Q()
            for range_str in private_ranges:
                network = ipaddress.ip_network(range_str)
                q |= (
                    Q(src_ip__startswith=str(network).split('/')[0][:3]) &
                    Q(dst_ip__startswith=str(network).split('/')[0][:3])
                )
            return queryset.filter(q)
        
        elif value == 'inbound':
            # IP origen externa, destino interno
            return queryset.filter(
                Q(src_ip__startswith='10.') | Q(src_ip__startswith='172.') | Q(src_ip__startswith='192.168.')
            ).exclude(
                Q(dst_ip__startswith='10.') | Q(dst_ip__startswith='172.') | Q(dst_ip__startswith='192.168.')
            )
        
        elif value == 'outbound':
            # IP origen interna, destino externo
            return queryset.filter(
                Q(dst_ip__startswith='10.') | Q(dst_ip__startswith='172.') | Q(dst_ip__startswith='192.168.')
            ).exclude(
                Q(src_ip__startswith='10.') | Q(src_ip__startswith='172.') | Q(src_ip__startswith='192.168.')
            )
        
        elif value == 'external':
            # Ambas IPs externas
            return queryset.exclude(
                Q(src_ip__startswith='10.') | Q(src_ip__startswith='172.') | Q(src_ip__startswith='192.168.') |
                Q(dst_ip__startswith='10.') | Q(dst_ip__startswith='172.') | Q(dst_ip__startswith='192.168.')
            )
        
        return queryset
    
    def general_search(self, queryset, name, value):
        """Búsqueda general en múltiples campos"""
        if not value:
            return queryset
        
        return queryset.filter(
            Q(src_ip__icontains=value) |
            Q(dst_ip__icontains=value) |
            Q(src_port__icontains=value) |
            Q(dst_port__icontains=value) |
            Q(protocol__icontains=value) |
            Q(archivo_origen__icontains=value)
        )


class CaptureSessionFilter(django_filters.FilterSet):
    """Filtro para sesiones de captura"""
    
    # Filtro de estado
    status = django_filters.ChoiceFilter(
        choices=[('', 'Todos los estados')] + CaptureSession.STATUS_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    # Filtro de interfaz
    interface = django_filters.CharFilter(
        field_name='interface',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Interfaz'})
    )
    
    # Filtros de fecha
    created_from = django_filters.DateFilter(
        field_name='created_at',
        lookup_expr='date__gte',
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
    )
    created_to = django_filters.DateFilter(
        field_name='created_at',
        lookup_expr='date__lte',
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
    )
    
    # Filtro de usuario
    started_by = django_filters.CharFilter(
        field_name='started_by__username',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Usuario'})
    )
    
    class Meta:
        model = CaptureSession
        fields = []


class TrafficStatisticsFilter(django_filters.FilterSet):
    """Filtro para estadísticas de tráfico"""
    
    # Filtros de fecha
    date_from = django_filters.DateFilter(
        field_name='date',
        lookup_expr='gte',
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
    )
    date_to = django_filters.DateFilter(
        field_name='date',
        lookup_expr='lte',
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
    )
    
    # Filtro de hora
    hour_from = django_filters.NumberFilter(
        field_name='hour',
        lookup_expr='gte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'min': '0', 'max': '23'})
    )
    hour_to = django_filters.NumberFilter(
        field_name='hour',
        lookup_expr='lte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'min': '0', 'max': '23'})
    )
    
    # Filtro de porcentaje de anomalías
    anomaly_threshold = django_filters.NumberFilter(
        method='filter_by_anomaly_threshold',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': '% mínimo de anomalías'})
    )
    
    class Meta:
        model = TrafficStatistics
        fields = []
    
    def filter_by_anomaly_threshold(self, queryset, name, value):
        """Filtrar por umbral de anomalías"""
        if value is None:
            return queryset
        
        # Calcular porcentaje de anomalías y filtrar
        return queryset.extra(
            where=[
                "CASE WHEN total_packets > 0 THEN (anomalous_packets * 100.0 / total_packets) ELSE 0 END >= %s"
            ],
            params=[value]
        )


class AdvancedTrafficFilter(TrafficFilter):
    """Filtro avanzado con opciones adicionales"""
    
    # Filtros de flujo
    flow_bytes_min = django_filters.NumberFilter(
        field_name='flow_bytes_per_sec',
        lookup_expr='gte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Bytes/seg mín.'})
    )
    flow_bytes_max = django_filters.NumberFilter(
        field_name='flow_bytes_per_sec',
        lookup_expr='lte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Bytes/seg máx.'})
    )
    
    flow_packets_min = django_filters.NumberFilter(
        field_name='flow_packets_per_sec',
        lookup_expr='gte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Paquetes/seg mín.'})
    )
    flow_packets_max = django_filters.NumberFilter(
        field_name='flow_packets_per_sec',
        lookup_expr='lte',
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Paquetes/seg máx.'})
    )
    
    # Filtro de puertos específicos
    COMMON_PORTS = [
        ('', 'Todos los puertos'),
        ('web', 'Web (80, 443, 8080, 8443)'),
        ('mail', 'Email (25, 110, 143, 465, 587, 993, 995)'),
        ('db', 'Base de datos (3306, 5432, 1433, 1521)'),
        ('remote', 'Acceso remoto (22, 23, 3389, 5900)'),
        ('dns', 'DNS (53)'),
        ('file', 'Transferencia (20, 21, 69)'),
        ('custom', 'Personalizado'),
    ]
    
    port_category = django_filters.ChoiceFilter(
        choices=COMMON_PORTS,
        method='filter_by_port_category',
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    # Filtro de rango de IPs
    ip_range = django_filters.CharFilter(
        method='filter_by_ip_range',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Rango IP (ej: 192.168.1.0/24)'})
    )
    
    # Filtro de flags TCP
    tcp_flags = django_filters.CharFilter(
        field_name='tcp_flags',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'TCP Flags'})
    )
    
    # Filtros booleanos avanzados
    is_anomaly = django_filters.BooleanFilter(
        method='filter_is_anomaly',
        widget=forms.Select(
            choices=[('', 'Todos'), (True, 'Solo anomalías'), (False, 'Solo normales')],
            attrs={'class': 'form-select'}
        )
    )
    
    has_high_confidence = django_filters.BooleanFilter(
        method='filter_high_confidence',
        widget=forms.Select(
            choices=[('', 'Todos'), (True, 'Alta confianza (>0.8)'), (False, 'Baja confianza (<=0.8)')],
            attrs={'class': 'form-select'}
        )
    )
    
    def filter_by_port_category(self, queryset, name, value):
        """Filtrar por categoría de puerto"""
        if not value:
            return queryset
        
        port_mappings = {
            'web': [80, 443, 8080, 8443],
            'mail': [25, 110, 143, 465, 587, 993, 995],
            'db': [3306, 5432, 1433, 1521],
            'remote': [22, 23, 3389, 5900],
            'dns': [53],
            'file': [20, 21, 69],
        }
        
        if value in port_mappings:
            ports = port_mappings[value]
            return queryset.filter(
                Q(src_port__in=ports) | Q(dst_port__in=ports)
            )
        
        return queryset
    
    def filter_by_ip_range(self, queryset, name, value):
        """Filtrar por rango de IP"""
        if not value:
            return queryset
        
        try:
            import ipaddress
            network = ipaddress.ip_network(value, strict=False)
            
            # Convertir a string pattern para filtro de base de datos
            network_str = str(network.network_address)
            prefix_length = network.prefixlen
            
            # Para simplicidad, usar startswith con los primeros octetos
            if prefix_length >= 24:  # /24 o mayor
                prefix = '.'.join(network_str.split('.')[:3])
                return queryset.filter(
                    Q(src_ip__startswith=prefix) | Q(dst_ip__startswith=prefix)
                )
            elif prefix_length >= 16:  # /16
                prefix = '.'.join(network_str.split('.')[:2])
                return queryset.filter(
                    Q(src_ip__startswith=prefix) | Q(dst_ip__startswith=prefix)
                )
            elif prefix_length >= 8:  # /8
                prefix = network_str.split('.')[0]
                return queryset.filter(
                    Q(src_ip__startswith=prefix) | Q(dst_ip__startswith=prefix)
                )
        
        except ValueError:
            # Si no es un rango válido, tratar como IP individual
            return queryset.filter(
                Q(src_ip=value) | Q(dst_ip=value)
            )
        
        return queryset
    
    def filter_is_anomaly(self, queryset, name, value):
        """Filtrar anomalías"""
        if value is None:
            return queryset
        
        if value:
            return queryset.filter(label__in=['ANOMALO', 'SOSPECHOSO', 'MALICIOSO'])
        else:
            return queryset.exclude(label__in=['ANOMALO', 'SOSPECHOSO', 'MALICIOSO'])
    
    def filter_high_confidence(self, queryset, name, value):
        """Filtrar por alta confianza"""
        if value is None:
            return queryset
        
        if value:
            return queryset.filter(confidence_score__gt=0.8)
        else:
            return queryset.filter(confidence_score__lte=0.8)