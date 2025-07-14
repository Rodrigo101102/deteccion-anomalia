from django.shortcuts import render
from django.http import JsonResponse
from django.views.generic import ListView
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import ModeloPrediccion, ModelStatistics
from .ml_models import PredictorAnomalias


@method_decorator(login_required, name='dispatch')
class PredictionListView(ListView):
    model = ModeloPrediccion
    template_name = 'prediction/prediction_list.html'
    context_object_name = 'predictions'
    paginate_by = 20
    ordering = ['-fecha_prediccion']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        prediction_type = self.request.GET.get('type')
        if prediction_type:
            queryset = queryset.filter(prediccion=prediction_type)
        return queryset


class PredictionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ModeloPrediccion.objects.all()
    
    @action(detail=False, methods=['post'])
    def predict_batch(self, request):
        """Ejecutar predicción en lote"""
        try:
            predictor = PredictorAnomalias()
            count = predictor.predecir_anomalias()
            return Response({
                'status': 'success',
                'predictions_made': count
            })
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Obtener estadísticas del modelo"""
        stats = ModelStatistics.objects.first()
        if not stats:
            return Response({
                'accuracy': 0,
                'precision': 0,
                'recall': 0,
                'f1_score': 0,
                'total_predictions': 0,
                'anomalies_detected': 0
            })
        
        return Response({
            'accuracy': stats.accuracy,
            'precision': stats.precision,
            'recall': stats.recall,
            'f1_score': stats.f1_score,
            'total_predictions': stats.total_predictions,
            'anomalies_detected': stats.anomalies_detected
        })