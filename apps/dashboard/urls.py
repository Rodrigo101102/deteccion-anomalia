from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.DashboardHomeView.as_view(), name='home'),
    path('traffic/', views.TrafficListView.as_view(), name='traffic_list'),
    path('alerts/', views.AlertsView.as_view(), name='alerts'),
    path('statistics/', views.StatisticsView.as_view(), name='statistics'),
    
    # API endpoints
    path('api/traffic-stats/', views.api_traffic_stats, name='api_traffic_stats'),
    path('api/protocol-distribution/', views.api_protocol_distribution, name='api_protocol_distribution'),
    path('api/anomaly-trend/', views.api_anomaly_trend, name='api_anomaly_trend'),
]