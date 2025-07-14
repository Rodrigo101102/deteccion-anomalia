"""
Modelos para gestión de tráfico de red.
"""

from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth import get_user_model
import ipaddress

User = get_user_model()


class TraficoRed(models.Model):
    """Modelo principal para almacenar datos de tráfico de red"""
    
    PROTOCOL_CHOICES = [
        ('TCP', 'TCP'),
        ('UDP', 'UDP'),
        ('ICMP', 'ICMP'),
        ('HTTP', 'HTTP'),
        ('HTTPS', 'HTTPS'),
        ('FTP', 'FTP'),
        ('SSH', 'SSH'),
        ('DNS', 'DNS'),
        ('SMTP', 'SMTP'),
        ('OTHER', 'Otro'),
    ]
    
    LABEL_CHOICES = [
        ('NORMAL', 'Normal'),
        ('ANOMALO', 'Anómalo'),
        ('SOSPECHOSO', 'Sospechoso'),
        ('BENIGNO', 'Benigno'),
        ('MALICIOSO', 'Malicioso'),
    ]
    
    # Campos principales de identificación de flujo
    src_ip = models.GenericIPAddressField(
        verbose_name='IP Origen',
        help_text='Dirección IP de origen del tráfico'
    )
    dst_ip = models.GenericIPAddressField(
        verbose_name='IP Destino',
        help_text='Dirección IP de destino del tráfico'
    )
    src_port = models.PositiveIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(65535)],
        verbose_name='Puerto Origen',
        help_text='Puerto de origen (0-65535)'
    )
    dst_port = models.PositiveIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(65535)],
        verbose_name='Puerto Destino',
        help_text='Puerto de destino (0-65535)'
    )
    protocol = models.CharField(
        max_length=10,
        choices=PROTOCOL_CHOICES,
        default='TCP',
        verbose_name='Protocolo',
        help_text='Protocolo de red utilizado'
    )
    
    # Métricas de tráfico
    packet_size = models.PositiveIntegerField(
        default=0,
        verbose_name='Tamaño de Paquete (bytes)',
        help_text='Tamaño total del paquete en bytes'
    )
    duration = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0)],
        verbose_name='Duración (segundos)',
        help_text='Duración de la conexión en segundos'
    )
    flow_bytes_per_sec = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0)],
        verbose_name='Bytes por Segundo',
        help_text='Flujo de bytes por segundo'
    )
    flow_packets_per_sec = models.FloatField(
        default=0.0,
        validators=[MinValueValidator(0.0)],
        verbose_name='Paquetes por Segundo',
        help_text='Flujo de paquetes por segundo'
    )
    
    # Campos adicionales de análisis
    total_fwd_packets = models.PositiveIntegerField(
        default=0,
        verbose_name='Paquetes Forward Total'
    )
    total_backward_packets = models.PositiveIntegerField(
        default=0,
        verbose_name='Paquetes Backward Total'
    )
    total_length_fwd_packets = models.PositiveIntegerField(
        default=0,
        verbose_name='Longitud Total Paquetes Forward'
    )
    total_length_backward_packets = models.PositiveIntegerField(
        default=0,
        verbose_name='Longitud Total Paquetes Backward'
    )
    
    # Estadísticas de tiempo
    fwd_packet_length_max = models.PositiveIntegerField(
        default=0,
        verbose_name='Longitud Máxima Paquete Forward'
    )
    fwd_packet_length_min = models.PositiveIntegerField(
        default=0,
        verbose_name='Longitud Mínima Paquete Forward'
    )
    fwd_packet_length_mean = models.FloatField(
        default=0.0,
        verbose_name='Longitud Promedio Paquete Forward'
    )
    fwd_packet_length_std = models.FloatField(
        default=0.0,
        verbose_name='Desviación Estándar Longitud Forward'
    )
    
    # Flags TCP
    tcp_flags = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Flags TCP'
    )
    
    # Etiquetado y clasificación
    label = models.CharField(
        max_length=50,
        choices=LABEL_CHOICES,
        null=True,
        blank=True,
        verbose_name='Etiqueta',
        help_text='Clasificación del tráfico'
    )
    confidence_score = models.FloatField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
        verbose_name='Puntuación de Confianza',
        help_text='Confianza de la predicción (0.0-1.0)'
    )
    
    # Metadatos del sistema
    fecha_captura = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha de Captura',
        help_text='Fecha y hora de captura del tráfico'
    )
    procesado = models.BooleanField(
        default=False,
        verbose_name='Procesado',
        help_text='Indica si el registro ha sido procesado por ML'
    )
    archivo_origen = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name='Archivo Origen',
        help_text='Archivo PCAP o CSV de origen'
    )
    
    # Campos de auditoría
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name='Creado por'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Última Actualización'
    )
    
    class Meta:
        db_table = 'traficoRed'
        verbose_name = 'Tráfico de Red'
        verbose_name_plural = 'Tráfico de Red'
        ordering = ['-fecha_captura']
        indexes = [
            models.Index(fields=['fecha_captura']),
            models.Index(fields=['label']),
            models.Index(fields=['procesado']),
            models.Index(fields=['src_ip', 'dst_ip']),
            models.Index(fields=['src_port', 'dst_port']),
            models.Index(fields=['protocol']),
            models.Index(fields=['confidence_score']),
        ]
    
    def __str__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.protocol})"
    
    @property
    def is_anomaly(self):
        """Verifica si el tráfico es anómalo"""
        return self.label in ['ANOMALO', 'SOSPECHOSO', 'MALICIOSO']
    
    @property
    def is_private_source(self):
        """Verifica si la IP origen es privada"""
        try:
            ip = ipaddress.ip_address(self.src_ip)
            return ip.is_private
        except ValueError:
            return False
    
    @property
    def is_private_destination(self):
        """Verifica si la IP destino es privada"""
        try:
            ip = ipaddress.ip_address(self.dst_ip)
            return ip.is_private
        except ValueError:
            return False
    
    @property
    def traffic_direction(self):
        """Determina la dirección del tráfico"""
        if self.is_private_source and not self.is_private_destination:
            return 'SALIENTE'
        elif not self.is_private_source and self.is_private_destination:
            return 'ENTRANTE'
        elif self.is_private_source and self.is_private_destination:
            return 'INTERNO'
        else:
            return 'EXTERNO'
    
    def get_flow_identifier(self):
        """Obtiene identificador único del flujo"""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"
    
    def calculate_throughput(self):
        """Calcula el throughput del flujo"""
        if self.duration > 0:
            return self.packet_size / self.duration
        return 0
    
    def is_high_volume(self, threshold=1000000):  # 1MB por defecto
        """Verifica si es tráfico de alto volumen"""
        return self.packet_size > threshold
    
    def is_suspicious_port(self):
        """Verifica si usa puertos sospechosos"""
        suspicious_ports = [
            1433, 1521, 3306, 5432,  # Bases de datos
            22, 23, 21, 25,           # Servicios remotos
            135, 139, 445,            # SMB/NetBIOS
            53, 69, 161,              # DNS, TFTP, SNMP
        ]
        return self.dst_port in suspicious_ports or self.src_port in suspicious_ports


class CaptureSession(models.Model):
    """Sesión de captura de tráfico"""
    
    STATUS_CHOICES = [
        ('PENDING', 'Pendiente'),
        ('RUNNING', 'En Ejecución'),
        ('COMPLETED', 'Completada'),
        ('FAILED', 'Fallida'),
        ('CANCELLED', 'Cancelada'),
    ]
    
    session_id = models.CharField(
        max_length=100,
        unique=True,
        verbose_name='ID de Sesión'
    )
    interface = models.CharField(
        max_length=50,
        default='eth0',
        verbose_name='Interfaz de Red'
    )
    duration = models.PositiveIntegerField(
        verbose_name='Duración (segundos)'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='PENDING',
        verbose_name='Estado'
    )
    pcap_file_path = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        verbose_name='Ruta Archivo PCAP'
    )
    csv_file_path = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        verbose_name='Ruta Archivo CSV'
    )
    packets_captured = models.PositiveIntegerField(
        default=0,
        verbose_name='Paquetes Capturados'
    )
    bytes_captured = models.PositiveBigIntegerField(
        default=0,
        verbose_name='Bytes Capturados'
    )
    error_message = models.TextField(
        blank=True,
        null=True,
        verbose_name='Mensaje de Error'
    )
    
    # Metadatos
    started_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name='Iniciado por'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha de Creación'
    )
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Fecha de Inicio'
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Fecha de Finalización'
    )
    
    class Meta:
        verbose_name = 'Sesión de Captura'
        verbose_name_plural = 'Sesiones de Captura'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Sesión {self.session_id} - {self.get_status_display()}"
    
    def start_capture(self):
        """Inicia la captura"""
        self.status = 'RUNNING'
        self.started_at = timezone.now()
        self.save()
    
    def complete_capture(self, packets=0, bytes_captured=0):
        """Completa la captura"""
        self.status = 'COMPLETED'
        self.completed_at = timezone.now()
        self.packets_captured = packets
        self.bytes_captured = bytes_captured
        self.save()
    
    def fail_capture(self, error_message):
        """Marca la captura como fallida"""
        self.status = 'FAILED'
        self.completed_at = timezone.now()
        self.error_message = error_message
        self.save()
    
    @property
    def duration_actual(self):
        """Duración real de la captura"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0


class TrafficStatistics(models.Model):
    """Estadísticas agregadas de tráfico"""
    
    date = models.DateField(
        verbose_name='Fecha'
    )
    hour = models.PositiveIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(23)],
        verbose_name='Hora'
    )
    
    # Contadores de tráfico
    total_packets = models.PositiveIntegerField(
        default=0,
        verbose_name='Total de Paquetes'
    )
    total_bytes = models.PositiveBigIntegerField(
        default=0,
        verbose_name='Total de Bytes'
    )
    unique_flows = models.PositiveIntegerField(
        default=0,
        verbose_name='Flujos Únicos'
    )
    
    # Contadores por protocolo
    tcp_packets = models.PositiveIntegerField(default=0)
    udp_packets = models.PositiveIntegerField(default=0)
    icmp_packets = models.PositiveIntegerField(default=0)
    other_packets = models.PositiveIntegerField(default=0)
    
    # Contadores por dirección
    inbound_packets = models.PositiveIntegerField(default=0)
    outbound_packets = models.PositiveIntegerField(default=0)
    internal_packets = models.PositiveIntegerField(default=0)
    
    # Contadores de anomalías
    normal_packets = models.PositiveIntegerField(default=0)
    anomalous_packets = models.PositiveIntegerField(default=0)
    suspicious_packets = models.PositiveIntegerField(default=0)
    
    # Metadatos
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Estadística de Tráfico'
        verbose_name_plural = 'Estadísticas de Tráfico'
        unique_together = ['date', 'hour']
        ordering = ['-date', '-hour']
        indexes = [
            models.Index(fields=['date', 'hour']),
        ]
    
    def __str__(self):
        return f"Estadísticas {self.date} {self.hour:02d}:00"
    
    @property
    def anomaly_percentage(self):
        """Porcentaje de anomalías"""
        if self.total_packets > 0:
            return (self.anomalous_packets / self.total_packets) * 100
        return 0