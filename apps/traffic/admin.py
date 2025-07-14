"""
Administración de modelos de tráfico de red.
"""
from django.contrib import admin
from .models import TraficoRed, CaptureSession


@admin.register(TraficoRed)
class TraficoRedAdmin(admin.ModelAdmin):
    """
    Administración del modelo TraficoRed.
    """
    list_display = (
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 
        'protocol', 'label', 'procesado', 'fecha_captura'
    )
    list_filter = ('protocol', 'label', 'procesado', 'fecha_captura')
    search_fields = ('src_ip', 'dst_ip', 'src_port', 'dst_port')
    readonly_fields = ('created_at', 'updated_at', 'flow_key')
    list_per_page = 50
    
    fieldsets = (
        ('Información del Flujo', {
            'fields': ('src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol')
        }),
        ('Características', {
            'fields': (
                'packet_size', 'duration', 'flow_bytes_per_sec', 
                'flow_packets_per_sec', 'total_fwd_packets', 
                'total_backward_packets', 'flow_iat_mean'
            )
        }),
        ('Predicción', {
            'fields': ('label', 'confidence_score', 'procesado')
        }),
        ('Metadatos', {
            'fields': ('fecha_captura', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(CaptureSession)
class CaptureSessionAdmin(admin.ModelAdmin):
    """
    Administración del modelo CaptureSession.
    """
    list_display = (
        'session_id', 'status', 'total_packets', 
        'start_time', 'end_time', 'created_at'
    )
    list_filter = ('status', 'start_time')
    search_fields = ('session_id',)
    readonly_fields = ('created_at',)