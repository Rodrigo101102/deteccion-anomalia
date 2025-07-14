"""
Modelos para el manejo de tráfico de red.
"""
from django.db import models
from django.utils import timezone


class TraficoRed(models.Model):
    """
    Modelo para almacenar los datos de tráfico de red capturados.
    """
    PROTOCOL_CHOICES = [
        ('TCP', 'TCP'),
        ('UDP', 'UDP'),
        ('ICMP', 'ICMP'),
        ('HTTP', 'HTTP'),
        ('HTTPS', 'HTTPS'),
        ('FTP', 'FTP'),
        ('SSH', 'SSH'),
        ('OTHER', 'Otro'),
    ]
    
    LABEL_CHOICES = [
        ('NORMAL', 'Normal'),
        ('ANOMALO', 'Anómalo'),
        ('PENDIENTE', 'Pendiente'),
    ]
    
    # Campos de identificación de flujo
    src_ip = models.GenericIPAddressField(verbose_name='IP Origen')
    dst_ip = models.GenericIPAddressField(verbose_name='IP Destino')
    src_port = models.PositiveIntegerField(verbose_name='Puerto Origen')
    dst_port = models.PositiveIntegerField(verbose_name='Puerto Destino')
    protocol = models.CharField(
        max_length=10,
        choices=PROTOCOL_CHOICES,
        default='TCP',
        verbose_name='Protocolo'
    )
    
    # Campos de características del flujo
    packet_size = models.PositiveIntegerField(verbose_name='Tamaño de Paquete (bytes)')
    duration = models.FloatField(verbose_name='Duración (segundos)')
    flow_bytes_per_sec = models.FloatField(
        verbose_name='Bytes por Segundo',
        null=True,
        blank=True
    )
    flow_packets_per_sec = models.FloatField(
        verbose_name='Paquetes por Segundo',
        null=True,
        blank=True
    )
    
    # Campos adicionales para análisis
    total_fwd_packets = models.PositiveIntegerField(
        verbose_name='Total Paquetes Forward',
        default=0
    )
    total_backward_packets = models.PositiveIntegerField(
        verbose_name='Total Paquetes Backward',
        default=0
    )
    flow_iat_mean = models.FloatField(
        verbose_name='Tiempo Inter-Arrival Promedio',
        null=True,
        blank=True
    )
    
    # Campos de estado y metadatos
    label = models.CharField(
        max_length=50,
        choices=LABEL_CHOICES,
        default='PENDIENTE',
        null=True,
        blank=True,
        verbose_name='Etiqueta de Predicción'
    )
    fecha_captura = models.DateTimeField(
        default=timezone.now,
        verbose_name='Fecha de Captura'
    )
    procesado = models.BooleanField(
        default=False,
        verbose_name='Procesado'
    )
    confidence_score = models.FloatField(
        verbose_name='Puntuación de Confianza',
        null=True,
        blank=True,
        help_text='Puntuación de confianza de la predicción (0-1)'
    )
    
    # Metadatos del sistema
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Creado')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Actualizado')
    
    class Meta:
        verbose_name = 'Tráfico de Red'
        verbose_name_plural = 'Tráfico de Red'
        ordering = ['-fecha_captura']
        indexes = [
            models.Index(fields=['src_ip']),
            models.Index(fields=['dst_ip']),
            models.Index(fields=['fecha_captura']),
            models.Index(fields=['label']),
            models.Index(fields=['procesado']),
        ]
    
    def __str__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.protocol})"
    
    @property
    def is_anomalous(self):
        """Verifica si el tráfico es anómalo."""
        return self.label == 'ANOMALO'
    
    @property
    def flow_key(self):
        """Genera una clave única para identificar el flujo."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"


class CaptureSession(models.Model):
    """
    Modelo para rastrear sesiones de captura de tráfico.
    """
    session_id = models.CharField(max_length=100, unique=True, verbose_name='ID de Sesión')
    start_time = models.DateTimeField(verbose_name='Hora de Inicio')
    end_time = models.DateTimeField(null=True, blank=True, verbose_name='Hora de Fin')
    total_packets = models.PositiveIntegerField(default=0, verbose_name='Total de Paquetes')
    pcap_file_path = models.CharField(
        max_length=500,
        null=True,
        blank=True,
        verbose_name='Ruta del Archivo PCAP'
    )
    csv_file_path = models.CharField(
        max_length=500,
        null=True,
        blank=True,
        verbose_name='Ruta del Archivo CSV'
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ('CAPTURING', 'Capturando'),
            ('PROCESSING', 'Procesando'),
            ('COMPLETED', 'Completado'),
            ('FAILED', 'Fallido'),
        ],
        default='CAPTURING',
        verbose_name='Estado'
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Creado')
    
    class Meta:
        verbose_name = 'Sesión de Captura'
        verbose_name_plural = 'Sesiones de Captura'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Sesión {self.session_id} - {self.get_status_display()}"