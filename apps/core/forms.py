"""
Formularios para la aplicación core.
"""

from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import CustomUser, SystemConfiguration


class CustomUserCreationForm(UserCreationForm):
    """Formulario para crear usuarios personalizados"""
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'role', 'department', 'phone')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].required = True
        self.fields['first_name'].required = True
        self.fields['last_name'].required = True
        
        # Añadir clases CSS de Bootstrap
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})


class CustomUserChangeForm(UserChangeForm):
    """Formulario para modificar usuarios personalizados"""
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'role', 'department', 'phone', 'is_active')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remover el campo de password
        if 'password' in self.fields:
            del self.fields['password']
        
        # Añadir clases CSS de Bootstrap
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})


class UserProfileForm(forms.ModelForm):
    """Formulario para que los usuarios editen su perfil"""
    
    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'phone', 'department')
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'department': forms.TextInput(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].required = True


class SystemConfigurationForm(forms.ModelForm):
    """Formulario para configuración del sistema"""
    
    class Meta:
        model = SystemConfiguration
        fields = [
            'capture_interval', 'capture_duration', 'auto_start_capture', 'network_interface',
            'batch_size', 'auto_process_csv', 'auto_predict',
            'ml_contamination', 'retrain_interval',
            'alert_threshold', 'email_alerts',
            'retention_days'
        ]
        widgets = {
            'capture_interval': forms.NumberInput(attrs={'class': 'form-control', 'min': '5', 'max': '3600'}),
            'capture_duration': forms.NumberInput(attrs={'class': 'form-control', 'min': '10', 'max': '7200'}),
            'auto_start_capture': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'network_interface': forms.TextInput(attrs={'class': 'form-control'}),
            'batch_size': forms.NumberInput(attrs={'class': 'form-control', 'min': '10', 'max': '10000'}),
            'auto_process_csv': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'auto_predict': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'ml_contamination': forms.NumberInput(attrs={'class': 'form-control', 'min': '0.01', 'max': '0.5', 'step': '0.01'}),
            'retrain_interval': forms.NumberInput(attrs={'class': 'form-control', 'min': '300', 'max': '86400'}),
            'alert_threshold': forms.NumberInput(attrs={'class': 'form-control', 'min': '0.1', 'max': '1.0', 'step': '0.1'}),
            'email_alerts': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'retention_days': forms.NumberInput(attrs={'class': 'form-control', 'min': '1', 'max': '365'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Organizar campos en secciones
        self.field_sections = {
            'Configuración de Captura': [
                'capture_interval', 'capture_duration', 'auto_start_capture', 'network_interface'
            ],
            'Configuración de Procesamiento': [
                'batch_size', 'auto_process_csv', 'auto_predict'
            ],
            'Configuración de Machine Learning': [
                'ml_contamination', 'retrain_interval'
            ],
            'Configuración de Alertas': [
                'alert_threshold', 'email_alerts'
            ],
            'Configuración de Retención': [
                'retention_days'
            ]
        }
    
    def clean_ml_contamination(self):
        """Validación personalizada para contaminación ML"""
        contamination = self.cleaned_data['ml_contamination']
        if not 0.01 <= contamination <= 0.5:
            raise forms.ValidationError('La contaminación debe estar entre 0.01 y 0.5')
        return contamination
    
    def clean_capture_interval(self):
        """Validación personalizada para intervalo de captura"""
        interval = self.cleaned_data['capture_interval']
        if interval < 5:
            raise forms.ValidationError('El intervalo mínimo es de 5 segundos')
        return interval


class AlertFilterForm(forms.Form):
    """Formulario para filtrar alertas"""
    
    severity = forms.ChoiceField(
        choices=[('', 'Todas las severidades')] + SystemAlert.SEVERITY_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    status = forms.ChoiceField(
        choices=[('', 'Todos los estados')] + SystemAlert.STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )