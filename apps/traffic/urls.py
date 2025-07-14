"""
URLs para la aplicación traffic.
"""

from django.urls import path
from . import views

app_name = 'traffic'

urlpatterns = [
    # Vistas principales
    path('', views.TrafficListView.as_view(), name='list'),
    path('<int:pk>/', views.TrafficDetailView.as_view(), name='detail'),
    path('analytics/', views.traffic_analytics_view, name='analytics'),
    
    # Pipeline completo
    path('pipeline/', views.traffic_pipeline_view, name='pipeline'),
    
    # Gestión de capturas
    path('capture/', views.capture_management_view, name='capture_management'),
    path('capture/start/', views.start_capture_view, name='start_capture'),
    path('capture/stop/', views.stop_capture_view, name='stop_capture'),
    path('capture/sessions/', views.CaptureSessionListView.as_view(), name='capture_sessions'),
    
    # Procesamiento de CSV
    path('processing/', views.csv_processing_view, name='csv_processing'),
    path('process/csv/', views.process_pending_csv_view, name='process_csv'),
    
    # Predicciones ML
    path('prediction/', views.ml_prediction_view, name='ml_prediction'),
    
    # APIs REST
    path('api/list/', views.traffic_api_list, name='api_list'),
    path('api/statistics/', views.traffic_statistics_api, name='api_statistics'),
    path('api/realtime/', views.traffic_realtime_data, name='api_realtime'),
    
    # Exportación
    path('export/', views.traffic_export_view, name='export'),
]