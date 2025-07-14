from django.contrib import admin
from django.db.models import Count, Sum
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe

from .models import TraficoRed, CaptureSession, TrafficStatistics


@admin.register(TraficoRed)
class TraficoRedAdmin(admin.ModelAdmin):
    """Admin para modelo TraficoRed"""
    
    list_display = (
        'id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'packet_size_formatted', 'label_colored', 'confidence_score',
        'procesado', 'fecha_captura'
    )
    list_filter = (
        'protocol', 'label', 'procesado', 'fecha_captura',
        'src_port', 'dst_port'
    )
    search_fields = (
        'src_ip', 'dst_ip', 'archivo_origen'
    )
    readonly_fields = (
        'id', 'fecha_captura', 'updated_at', 'traffic_direction',
        'is_anomaly', 'is_private_source', 'is_private_destination',
        'flow_identifier'
    )
    ordering = ('-fecha_captura',)
    date_hierarchy = 'fecha_captura'
    
    fieldsets = (
        ('Información de Red', {
            'fields': (
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'
            )
        }),
        ('Métricas de Tráfico', {
            'fields': (
                'packet_size', 'duration', 'flow_bytes_per_sec', 'flow_packets_per_sec',
                'total_fwd_packets', 'total_backward_packets'
            )
        }),
        ('Estadísticas de Paquetes', {
            'fields': (
                'fwd_packet_length_max', 'fwd_packet_length_min',
                'fwd_packet_length_mean', 'fwd_packet_length_std'
            ),
            'classes': ('collapse',)
        }),
        ('Clasificación', {
            'fields': (
                'label', 'confidence_score', 'tcp_flags'
            )
        }),
        ('Metadatos', {
            'fields': (
                'procesado', 'archivo_origen', 'created_by',
                'fecha_captura', 'updated_at'
            )
        }),
        ('Información Calculada', {
            'fields': (
                'traffic_direction', 'is_anomaly', 'is_private_source',
                'is_private_destination', 'flow_identifier'
            ),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['mark_as_processed', 'mark_as_anomaly', 'mark_as_normal', 'export_selected']
    
    def packet_size_formatted(self, obj):
        """Formatea el tamaño del paquete"""
        return f"{obj.packet_size:,} bytes"
    packet_size_formatted.short_description = 'Tamaño'
    
    def label_colored(self, obj):
        """Muestra la etiqueta con color"""
        if obj.label == 'ANOMALO':
            color = 'red'
        elif obj.label == 'NORMAL':
            color = 'green'
        elif obj.label == 'SOSPECHOSO':
            color = 'orange'
        else:
            color = 'gray'
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.label or 'Sin clasificar'
        )
    label_colored.short_description = 'Etiqueta'
    
    def flow_identifier(self, obj):
        """Muestra el identificador del flujo"""
        return obj.get_flow_identifier()
    flow_identifier.short_description = 'ID de Flujo'
    
    def get_queryset(self, request):
        """Optimiza las consultas"""
        return super().get_queryset(request).select_related('created_by')
    
    def mark_as_processed(self, request, queryset):
        """Marcar como procesado"""
        updated = queryset.update(procesado=True)
        self.message_user(request, f'{updated} registros marcados como procesados.')
    mark_as_processed.short_description = "Marcar como procesados"
    
    def mark_as_anomaly(self, request, queryset):
        """Marcar como anomalía"""
        updated = queryset.update(label='ANOMALO')
        self.message_user(request, f'{updated} registros marcados como anomalías.')
    mark_as_anomaly.short_description = "Marcar como anomalías"
    
    def mark_as_normal(self, request, queryset):
        """Marcar como normal"""
        updated = queryset.update(label='NORMAL')
        self.message_user(request, f'{updated} registros marcados como normales.')
    mark_as_normal.short_description = "Marcar como normales"
    
    def export_selected(self, request, queryset):
        """Exportar registros seleccionados"""
        from apps.core.utils import export_data_to_csv
        
        fields = [
            'id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'packet_size', 'duration', 'label', 'confidence_score', 'fecha_captura'
        ]
        
        return export_data_to_csv(
            queryset=queryset,
            fields=fields,
            filename=f'traffic_export_{queryset.count()}_records.csv'
        )
    export_selected.short_description = "Exportar seleccionados a CSV"


@admin.register(CaptureSession)
class CaptureSessionAdmin(admin.ModelAdmin):
    """Admin para sesiones de captura"""
    
    list_display = (
        'session_id', 'interface', 'status_colored', 'duration',
        'packets_captured', 'bytes_captured_formatted',
        'started_by', 'created_at'
    )
    list_filter = ('status', 'interface', 'created_at')
    search_fields = ('session_id', 'started_by__username')
    readonly_fields = (
        'session_id', 'packets_captured', 'bytes_captured',
        'created_at', 'started_at', 'completed_at', 'duration_actual'
    )
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Información de Sesión', {
            'fields': ('session_id', 'interface', 'duration', 'status')
        }),
        ('Archivos Generados', {
            'fields': ('pcap_file_path', 'csv_file_path')
        }),
        ('Resultados', {
            'fields': ('packets_captured', 'bytes_captured', 'error_message')
        }),
        ('Timestamps', {
            'fields': (
                'created_at', 'started_at', 'completed_at', 'duration_actual'
            ),
            'classes': ('collapse',)
        }),
        ('Usuario', {
            'fields': ('started_by',)
        }),
    )
    
    def status_colored(self, obj):
        """Muestra el estado con color"""
        colors = {
            'PENDING': 'orange',
            'RUNNING': 'blue',
            'COMPLETED': 'green',
            'FAILED': 'red',
            'CANCELLED': 'gray'
        }
        color = colors.get(obj.status, 'black')
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_colored.short_description = 'Estado'
    
    def bytes_captured_formatted(self, obj):
        """Formatea bytes capturados"""
        from apps.traffic.utils import formatear_bytes
        return formatear_bytes(obj.bytes_captured)
    bytes_captured_formatted.short_description = 'Bytes Capturados'
    
    def duration_actual(self, obj):
        """Duración real de la captura"""
        return f"{obj.duration_actual:.1f}s" if obj.duration_actual else "N/A"
    duration_actual.short_description = 'Duración Real'
    
    def get_queryset(self, request):
        """Optimiza las consultas"""
        return super().get_queryset(request).select_related('started_by')


@admin.register(TrafficStatistics)
class TrafficStatisticsAdmin(admin.ModelAdmin):
    """Admin para estadísticas de tráfico"""
    
    list_display = (
        'datetime_display', 'total_packets', 'anomaly_percentage_display',
        'unique_flows', 'tcp_packets', 'udp_packets'
    )
    list_filter = ('date', 'hour')
    ordering = ('-date', '-hour')
    date_hierarchy = 'date'
    readonly_fields = ('anomaly_percentage', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Período', {
            'fields': ('date', 'hour')
        }),
        ('Contadores Generales', {
            'fields': (
                'total_packets', 'total_bytes', 'unique_flows',
                'anomaly_percentage'
            )
        }),
        ('Por Protocolo', {
            'fields': (
                'tcp_packets', 'udp_packets', 'icmp_packets', 'other_packets'
            )
        }),
        ('Por Dirección', {
            'fields': (
                'inbound_packets', 'outbound_packets', 'internal_packets'
            )
        }),
        ('Por Clasificación', {
            'fields': (
                'normal_packets', 'anomalous_packets', 'suspicious_packets'
            )
        }),
        ('Metadatos', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def datetime_display(self, obj):
        """Muestra fecha y hora combinadas"""
        return f"{obj.date} {obj.hour:02d}:00"
    datetime_display.short_description = 'Fecha y Hora'
    
    def anomaly_percentage_display(self, obj):
        """Muestra porcentaje de anomalías con color"""
        percentage = obj.anomaly_percentage
        
        if percentage >= 20:
            color = 'red'
        elif percentage >= 10:
            color = 'orange'
        elif percentage >= 5:
            color = 'yellow'
        else:
            color = 'green'
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.1f}%</span>',
            color,
            percentage
        )
    anomaly_percentage_display.short_description = '% Anomalías'
    
    def get_queryset(self, request):
        """Añade datos calculados"""
        return super().get_queryset(request)


# Configuración del admin site
admin.site.site_header = 'Sistema de Detección de Anomalías - Administración'
admin.site.site_title = 'Admin Panel'
admin.site.index_title = 'Panel de Administración'

# Personalizar el admin index
def admin_index_stats(request):
    """Estadísticas para el index del admin"""
    from django.utils import timezone
    from datetime import timedelta
    
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    stats = {
        'total_traffic': TraficoRed.objects.count(),
        'traffic_24h': TraficoRed.objects.filter(fecha_captura__gte=last_24h).count(),
        'anomalies_24h': TraficoRed.objects.filter(
            fecha_captura__gte=last_24h,
            label='ANOMALO'
        ).count(),
        'active_sessions': CaptureSession.objects.filter(status='RUNNING').count(),
        'pending_processing': TraficoRed.objects.filter(procesado=False).count(),
    }
    
    return stats

# Agregar estadísticas al contexto del admin
def admin_context_processor(request):
    """Añade estadísticas al contexto del admin"""
    if request.path.startswith('/admin/'):
        try:
            return {'admin_stats': admin_index_stats(request)}
        except:
            return {}
    return {}