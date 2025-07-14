"""
URLs del dashboard.
"""
from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.index, name='index'),
    path('analysis/', views.traffic_analysis, name='analysis'),
    path('status/', views.system_status, name='status'),
]