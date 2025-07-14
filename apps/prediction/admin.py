from django.contrib import admin
from .models import ModeloPrediccion, ModelStatistics


@admin.register(ModeloPrediccion)
class ModeloPrediccionAdmin(admin.ModelAdmin):
    list_display = ['trafico', 'prediccion', 'confidence_score', 'modelo_version', 'fecha_prediccion']
    list_filter = ['prediccion', 'modelo_version', 'fecha_prediccion']
    search_fields = ['trafico__src_ip', 'trafico__dst_ip']
    readonly_fields = ['fecha_prediccion']
    ordering = ['-fecha_prediccion']


@admin.register(ModelStatistics)
class ModelStatisticsAdmin(admin.ModelAdmin):
    list_display = ['accuracy', 'precision', 'recall', 'f1_score', 'total_predictions', 'anomalies_detected', 'fecha_calculo']
    readonly_fields = ['fecha_calculo']
    ordering = ['-fecha_calculo']