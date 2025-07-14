"""
Formularios para la aplicación traffic.
"""

from django import forms
from django.core.validators import MinValueValidator, MaxValueValidator
from .models import CaptureSession
from .utils import obtener_interfaces_disponibles


class CaptureForm(forms.Form):
    """Formulario para iniciar captura de tráfico"""
    
    interface = forms.ChoiceField(
        label='Interfaz de Red',
        help_text='Selecciona la interfaz de red para capturar tráfico',
        widget=forms.Select(attrs={
            'class': 'form-select'
        })
    )
    
    duration = forms.ChoiceField(
        label='Duración de Captura',
        choices=[
            (60, '1 minuto'),
            (300, '5 minutos'),
            (600, '10 minutos'),
            (1800, '30 minutos'),
            (3600, '1 hora'),
        ],
        initial=300,
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        })
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Obtener interfaces disponibles dinámicamente
        interfaces = obtener_interfaces_disponibles()
        self.fields['interface'].choices = [(iface, iface) for iface in interfaces]
        
        # Establecer valor por defecto
        if 'eth0' in interfaces:
            self.fields['interface'].initial = 'eth0'
        elif interfaces:
            self.fields['interface'].initial = interfaces[0]


class CSVProcessingForm(forms.Form):
    """Formulario para procesamiento de CSV"""
    
    PROCESSING_CHOICES = [
        ('process_all', 'Procesar todos los archivos CSV'),
        ('process_file', 'Procesar archivo específico'),
    ]
    
    action = forms.ChoiceField(
        choices=PROCESSING_CHOICES,
        initial='process_all',
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        })
    )
    
    archivo = forms.CharField(
        required=False,
        max_length=255,
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text='Selecciona un archivo específico para procesar'
    )
    
    def __init__(self, archivos_disponibles=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        if archivos_disponibles:
            choices = [('', 'Seleccionar archivo...')] + [
                (archivo, archivo) for archivo in archivos_disponibles
            ]
            self.fields['archivo'].widget.choices = choices
    
    def clean(self):
        cleaned_data = super().clean()
        action = cleaned_data.get('action')
        archivo = cleaned_data.get('archivo')
        
        if action == 'process_file' and not archivo:
            raise forms.ValidationError(
                'Debes seleccionar un archivo cuando eliges procesar archivo específico'
            )
        
        return cleaned_data


class MLPredictionForm(forms.Form):
    """Formulario para ejecutar predicciones ML"""
    
    ACTION_CHOICES = [
        ('predict', 'Ejecutar predicciones'),
        ('train_model', 'Entrenar modelo'),
    ]
    
    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        initial='predict',
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        })
    )
    
    batch_size = forms.ChoiceField(
        label='Tamaño del Lote',
        choices=[
            (100, '100 registros'),
            (500, '500 registros'),
            (1000, '1,000 registros'),
            (2000, '2,000 registros'),
            (5000, '5,000 registros'),
        ],
        initial=1000,
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        }),
        help_text='Número de registros a procesar en cada lote'
    )
    
    def clean_batch_size(self):
        batch_size = self.cleaned_data['batch_size']
        try:
            return int(batch_size)
        except (ValueError, TypeError):
            raise forms.ValidationError('Tamaño de lote inválido')


class TrafficFilterForm(forms.Form):
    """Formulario para filtrar tráfico"""
    
    LABEL_CHOICES = [
        ('', 'Todos'),
        ('NORMAL', 'Normal'),
        ('ANOMALO', 'Anómalo'),
        ('SOSPECHOSO', 'Sospechoso'),
        ('BENIGNO', 'Benigno'),
        ('MALICIOSO', 'Malicioso'),
    ]
    
    PROTOCOL_CHOICES = [
        ('', 'Todos'),
        ('TCP', 'TCP'),
        ('UDP', 'UDP'),
        ('ICMP', 'ICMP'),
        ('HTTP', 'HTTP'),
        ('HTTPS', 'HTTPS'),
        ('DNS', 'DNS'),
        ('SSH', 'SSH'),
        ('FTP', 'FTP'),
        ('SMTP', 'SMTP'),
        ('OTHER', 'Otro'),
    ]
    
    label = forms.ChoiceField(
        choices=LABEL_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    protocol = forms.ChoiceField(
        choices=PROTOCOL_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    src_ip = forms.GenericIPAddressField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '192.168.1.1'
        })
    )
    
    dst_ip = forms.GenericIPAddressField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '192.168.1.1'
        })
    )
    
    src_port = forms.IntegerField(
        required=False,
        validators=[MinValueValidator(0), MaxValueValidator(65535)],
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': '80'
        })
    )
    
    dst_port = forms.IntegerField(
        required=False,
        validators=[MinValueValidator(0), MaxValueValidator(65535)],
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': '443'
        })
    )
    
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    def clean(self):
        cleaned_data = super().clean()
        date_from = cleaned_data.get('date_from')
        date_to = cleaned_data.get('date_to')
        
        if date_from and date_to and date_from > date_to:
            raise forms.ValidationError(
                'La fecha inicial no puede ser posterior a la fecha final'
            )
        
        return cleaned_data


class ExportForm(forms.Form):
    """Formulario para exportar datos"""
    
    FORMAT_CHOICES = [
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('xlsx', 'Excel'),
    ]
    
    format = forms.ChoiceField(
        choices=FORMAT_CHOICES,
        initial='csv',
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        })
    )
    
    include_fields = forms.MultipleChoiceField(
        choices=[
            ('src_ip', 'IP Origen'),
            ('dst_ip', 'IP Destino'),
            ('src_port', 'Puerto Origen'),
            ('dst_port', 'Puerto Destino'),
            ('protocol', 'Protocolo'),
            ('packet_size', 'Tamaño Paquete'),
            ('duration', 'Duración'),
            ('label', 'Etiqueta'),
            ('confidence_score', 'Puntuación Confianza'),
            ('fecha_captura', 'Fecha Captura'),
        ],
        initial=[
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'packet_size', 'label', 'fecha_captura'
        ],
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-check-input'
        }),
        help_text='Selecciona los campos a incluir en la exportación'
    )
    
    max_records = forms.IntegerField(
        label='Máximo de Registros',
        initial=10000,
        validators=[MinValueValidator(1), MaxValueValidator(100000)],
        widget=forms.NumberInput(attrs={
            'class': 'form-control'
        }),
        help_text='Límite de registros a exportar (máximo 100,000)'
    )