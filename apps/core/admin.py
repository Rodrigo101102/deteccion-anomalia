from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, SystemConfiguration, AuditLog, SystemAlert
from .forms import CustomUserCreationForm, CustomUserChangeForm


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """Admin para usuarios personalizados"""
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser
    
    list_display = ('username', 'email', 'role', 'department', 'is_active', 'last_activity')
    list_filter = ('role', 'is_active', 'is_staff', 'department')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    fieldsets = UserAdmin.fieldsets + (
        ('Información Adicional', {
            'fields': ('role', 'phone', 'department', 'last_activity', 'is_active_session')
        }),
    )
    
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Información Adicional', {
            'fields': ('role', 'phone', 'department')
        }),
    )
    
    readonly_fields = ('last_activity', 'is_active_session', 'date_joined', 'last_login')


@admin.register(SystemConfiguration)
class SystemConfigurationAdmin(admin.ModelAdmin):
    """Admin para configuración del sistema"""
    list_display = ('__str__', 'capture_interval', 'auto_start_capture', 'updated_by', 'updated_at')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Configuración de Captura', {
            'fields': ('capture_interval', 'capture_duration', 'auto_start_capture', 'network_interface')
        }),
        ('Configuración de Procesamiento', {
            'fields': ('batch_size', 'auto_process_csv', 'auto_predict')
        }),
        ('Configuración de Machine Learning', {
            'fields': ('ml_contamination', 'retrain_interval')
        }),
        ('Configuración de Alertas', {
            'fields': ('alert_threshold', 'email_alerts')
        }),
        ('Configuración de Retención', {
            'fields': ('retention_days',)
        }),
        ('Metadatos', {
            'fields': ('updated_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def has_add_permission(self, request):
        # Solo permitir una configuración
        return not SystemConfiguration.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        # No permitir eliminar la configuración
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin para logs de auditoría"""
    list_display = ('timestamp', 'user', 'action', 'description', 'ip_address')
    list_filter = ('action', 'timestamp')
    search_fields = ('user__username', 'description', 'ip_address')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)
    
    def has_add_permission(self, request):
        # No permitir añadir logs manualmente
        return False
    
    def has_change_permission(self, request, obj=None):
        # No permitir modificar logs
        return False


@admin.register(SystemAlert)
class SystemAlertAdmin(admin.ModelAdmin):
    """Admin para alertas del sistema"""
    list_display = ('title', 'severity', 'status', 'alert_type', 'created_at', 'acknowledged_by')
    list_filter = ('severity', 'status', 'alert_type', 'created_at')
    search_fields = ('title', 'description', 'source_ip', 'target_ip')
    readonly_fields = ('created_at', 'acknowledged_at', 'resolved_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('Información de la Alerta', {
            'fields': ('title', 'description', 'severity', 'status', 'alert_type')
        }),
        ('Datos de Red', {
            'fields': ('source_ip', 'target_ip', 'alert_data'),
            'classes': ('collapse',)
        }),
        ('Estado de la Alerta', {
            'fields': ('acknowledged_by', 'acknowledged_at', 'resolved_by', 'resolved_at'),
            'classes': ('collapse',)
        }),
        ('Metadatos', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['mark_acknowledged', 'mark_resolved', 'mark_false_positive']
    
    def mark_acknowledged(self, request, queryset):
        """Marcar alertas como reconocidas"""
        updated = 0
        for alert in queryset.filter(status='active'):
            alert.acknowledge(request.user)
            updated += 1
        
        self.message_user(request, f'{updated} alertas marcadas como reconocidas.')
    mark_acknowledged.short_description = "Marcar como reconocidas"
    
    def mark_resolved(self, request, queryset):
        """Marcar alertas como resueltas"""
        updated = 0
        for alert in queryset.filter(status__in=['active', 'acknowledged']):
            alert.resolve(request.user)
            updated += 1
        
        self.message_user(request, f'{updated} alertas marcadas como resueltas.')
    mark_resolved.short_description = "Marcar como resueltas"
    
    def mark_false_positive(self, request, queryset):
        """Marcar alertas como falsos positivos"""
        updated = 0
        for alert in queryset.filter(status__in=['active', 'acknowledged']):
            alert.mark_false_positive(request.user)
            updated += 1
        
        self.message_user(request, f'{updated} alertas marcadas como falsos positivos.')
    mark_false_positive.short_description = "Marcar como falsos positivos"