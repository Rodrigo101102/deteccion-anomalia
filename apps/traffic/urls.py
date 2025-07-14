"""
URLs de la aplicación de tráfico.
"""
from django.urls import path
from . import views

app_name = 'traffic'

urlpatterns = [
    path('', views.traffic_list, name='list'),
    path('start-capture/', views.start_capture, name='start_capture'),
    path('stop-capture/', views.stop_capture, name='stop_capture'),
    path('status/', views.capture_status, name='status'),
]