from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'prediction'

router = DefaultRouter()
router.register(r'api', views.PredictionViewSet)

urlpatterns = [
    path('', views.PredictionListView.as_view(), name='prediction_list'),
    path('', include(router.urls)),
]