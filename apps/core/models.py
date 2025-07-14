"""
Modelos principales del sistema de detección de anomalías.
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator


class CustomUser(AbstractUser):
    """Usuario personalizado con roles y configuraciones adicionales"""
    
    ROLE_CHOICES = [
        ('admin', 'Administrador'),
        ('analyst', 'Analista de Seguridad'),
        ('operator', 'Operador'),
        ('viewer', 'Solo Lectura'),
    ]
    
    role = models.CharField(
        max_length=20, 
        choices=ROLE_CHOICES, 
        default='viewer',
        verbose_name='Rol'
    )
    phone = models.CharField(
        max_length=20, 
        blank=True, 
        null=True,
        verbose_name='Teléfono'
    )
    department = models.CharField(
        max_length=100, 
        blank=True, 
        null=True,
        verbose_name='Departamento'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha de Creación'
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Última Actualización'
    )
    is_active_session = models.BooleanField(
        default=False,
        verbose_name='Sesión Activa'
    )
    last_activity = models.DateTimeField(
        null=True, 
        blank=True,
        verbose_name='Última Actividad'
    )
    
    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'
        ordering = ['-date_joined']
        
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
    
    def can_manage_users(self):
        """Verifica si el usuario puede gestionar otros usuarios"""
        return self.role in ['admin']
    
    def can_modify_config(self):
        """Verifica si puede modificar configuraciones del sistema"""
        return self.role in ['admin', 'analyst']
    
    def can_view_analytics(self):
        """Verifica si puede ver análisis avanzados"""
        return self.role in ['admin', 'analyst', 'operator']
    
    def update_last_activity(self):
        """Actualiza timestamp de última actividad"""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])


class SystemConfiguration(models.Model):
    """Configuración general del sistema"""
    
    # Configuración de captura
    capture_interval = models.IntegerField(
        default=20,
        validators=[MinValueValidator(5), MaxValueValidator(3600)],
        verbose_name='Intervalo de Captura (segundos)',
        help_text='Tiempo entre capturas automáticas de tráfico'
    )
    capture_duration = models.IntegerField(
        default=300,
        validators=[MinValueValidator(10), MaxValueValidator(7200)],
        verbose_name='Duración de Captura (segundos)',
        help_text='Duración de cada sesión de captura'
    )
    auto_start_capture = models.BooleanField(
        default=True,
        verbose_name='Inicio Automático',
        help_text='Iniciar captura automáticamente al acceder al sistema'
    )
    network_interface = models.CharField(
        max_length=50,
        default='eth0',
        verbose_name='Interfaz de Red',
        help_text='Interfaz de red para captura de tráfico'
    )
    
    # Configuración de procesamiento
    batch_size = models.IntegerField(
        default=1000,
        validators=[MinValueValidator(10), MaxValueValidator(10000)],
        verbose_name='Tamaño de Lote',
        help_text='Número de registros a procesar por lote'
    )
    auto_process_csv = models.BooleanField(
        default=True,
        verbose_name='Procesamiento Automático CSV',
        help_text='Procesar archivos CSV automáticamente'
    )
    auto_predict = models.BooleanField(
        default=True,
        verbose_name='Predicción Automática',
        help_text='Realizar predicciones automáticamente'
    )
    
    # Configuración de Machine Learning
    ml_contamination = models.FloatField(
        default=0.1,
        validators=[MinValueValidator(0.01), MaxValueValidator(0.5)],
        verbose_name='Contaminación ML',
        help_text='Porcentaje esperado de anomalías (0.01-0.5)'
    )
    retrain_interval = models.IntegerField(
        default=3600,
        validators=[MinValueValidator(300), MaxValueValidator(86400)],
        verbose_name='Intervalo de Reentrenamiento (segundos)',
        help_text='Frecuencia de reentrenamiento del modelo'
    )
    
    # Configuración de alertas
    alert_threshold = models.FloatField(
        default=0.8,
        validators=[MinValueValidator(0.1), MaxValueValidator(1.0)],
        verbose_name='Umbral de Alerta',
        help_text='Umbral de confianza para generar alertas'
    )
    email_alerts = models.BooleanField(
        default=False,
        verbose_name='Alertas por Email',
        help_text='Enviar alertas por correo electrónico'
    )
    
    # Configuración de retención
    retention_days = models.IntegerField(
        default=30,
        validators=[MinValueValidator(1), MaxValueValidator(365)],
        verbose_name='Días de Retención',
        help_text='Días para mantener datos históricos'
    )
    
    # Metadatos
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        verbose_name='Actualizado por'
    )
    
    class Meta:
        verbose_name = 'Configuración del Sistema'
        verbose_name_plural = 'Configuraciones del Sistema'
        
    def __str__(self):
        return f"Configuración - {self.updated_at.strftime('%Y-%m-%d %H:%M')}"
    
    @classmethod
    def get_current_config(cls):
        """Obtiene la configuración actual del sistema"""
        config, created = cls.objects.get_or_create(pk=1)
        return config


class AuditLog(models.Model):
    """Log de auditoría para el sistema"""
    
    ACTION_CHOICES = [
        ('login', 'Inicio de Sesión'),
        ('logout', 'Cierre de Sesión'),
        ('config_change', 'Cambio de Configuración'),
        ('capture_start', 'Inicio de Captura'),
        ('capture_stop', 'Fin de Captura'),
        ('csv_process', 'Procesamiento CSV'),
        ('prediction', 'Predicción Realizada'),
        ('model_train', 'Entrenamiento de Modelo'),
        ('alert_generated', 'Alerta Generada'),
        ('data_export', 'Exportación de Datos'),
        ('user_created', 'Usuario Creado'),
        ('user_modified', 'Usuario Modificado'),
        ('system_error', 'Error del Sistema'),
    ]
    
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name='Usuario'
    )
    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        verbose_name='Acción'
    )
    description = models.TextField(
        verbose_name='Descripción'
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name='Dirección IP'
    )
    user_agent = models.TextField(
        null=True,
        blank=True,
        verbose_name='User Agent'
    )
    additional_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name='Datos Adicionales'
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha y Hora'
    )
    
    class Meta:
        verbose_name = 'Log de Auditoría'
        verbose_name_plural = 'Logs de Auditoría'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
        ]
        
    def __str__(self):
        user_str = self.user.username if self.user else 'Sistema'
        return f"{user_str} - {self.get_action_display()} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"


class SystemAlert(models.Model):
    """Alertas del sistema"""
    
    SEVERITY_CHOICES = [
        ('low', 'Baja'),
        ('medium', 'Media'),
        ('high', 'Alta'),
        ('critical', 'Crítica'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Activa'),
        ('acknowledged', 'Reconocida'),
        ('resolved', 'Resuelta'),
        ('false_positive', 'Falso Positivo'),
    ]
    
    title = models.CharField(
        max_length=200,
        verbose_name='Título'
    )
    description = models.TextField(
        verbose_name='Descripción'
    )
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default='medium',
        verbose_name='Severidad'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active',
        verbose_name='Estado'
    )
    alert_type = models.CharField(
        max_length=50,
        verbose_name='Tipo de Alerta'
    )
    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name='IP Origen'
    )
    target_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name='IP Destino'
    )
    alert_data = models.JSONField(
        default=dict,
        verbose_name='Datos de la Alerta'
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha de Creación'
    )
    acknowledged_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Fecha de Reconocimiento'
    )
    acknowledged_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acknowledged_alerts',
        verbose_name='Reconocida por'
    )
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Fecha de Resolución'
    )
    resolved_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_alerts',
        verbose_name='Resuelta por'
    )
    
    class Meta:
        verbose_name = 'Alerta del Sistema'
        verbose_name_plural = 'Alertas del Sistema'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['created_at']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['status', 'created_at']),
        ]
        
    def __str__(self):
        return f"{self.title} - {self.get_severity_display()} - {self.get_status_display()}"
    
    def acknowledge(self, user):
        """Reconocer la alerta"""
        self.status = 'acknowledged'
        self.acknowledged_at = timezone.now()
        self.acknowledged_by = user
        self.save()
    
    def resolve(self, user):
        """Resolver la alerta"""
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.resolved_by = user
        self.save()
    
    def mark_false_positive(self, user):
        """Marcar como falso positivo"""
        self.status = 'false_positive'
        self.resolved_at = timezone.now()
        self.resolved_by = user
        self.save()