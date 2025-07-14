"""
URLs para la aplicación core.
"""

from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    # Vistas principales
    path('', views.home_view, name='home'),
    path('config/', views.SystemConfigurationView.as_view(), name='config'),
    path('profile/', views.user_profile_view, name='profile'),
    
    # Auditoría y logs
    path('audit/', views.AuditLogListView.as_view(), name='audit_logs'),
    
    # Alertas
    path('alerts/', views.SystemAlertListView.as_view(), name='alerts'),
    path('alerts/<int:alert_id>/action/', views.alert_action_view, name='alert_action'),
    
    # Gestión de usuarios (solo admin)
    path('users/', views.users_management_view, name='users_management'),
    path('users/<int:user_id>/toggle/', views.toggle_user_status, name='toggle_user_status'),
    
    # APIs
    path('api/system-stats/', views.system_stats_api, name='system_stats_api'),
    path('api/dashboard-data/', views.dashboard_data_api, name='dashboard_data_api'),
]