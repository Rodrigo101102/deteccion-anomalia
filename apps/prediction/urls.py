"""
URLs de la aplicación de predicción.
"""
from django.urls import path
from . import views

app_name = 'prediction'

urlpatterns = [
    path('', views.prediction_status, name='status'),
    path('process/', views.process_traffic, name='process'),
]