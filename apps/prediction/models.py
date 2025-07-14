from django.db import models
from apps.traffic.models import TraficoRed


class ModeloPrediccion(models.Model):
    """Modelo para almacenar predicciones de anomalías"""
    trafico = models.ForeignKey(
        TraficoRed, 
        on_delete=models.CASCADE, 
        related_name='predicciones'
    )
    prediccion = models.CharField(
        max_length=50, 
        choices=[
            ('NORMAL', 'Normal'),
            ('ANOMALO', 'Anómalo'),
        ]
    )
    confidence_score = models.FloatField(
        help_text="Puntuación de confianza de la predicción"
    )
    modelo_version = models.CharField(
        max_length=50, 
        default='isolation_forest_v1'
    )
    fecha_prediccion = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'predicciones'
        indexes = [
            models.Index(fields=['prediccion']),
            models.Index(fields=['fecha_prediccion']),
            models.Index(fields=['confidence_score']),
        ]
        verbose_name = 'Predicción'
        verbose_name_plural = 'Predicciones'
    
    def __str__(self):
        return f"Predicción {self.prediccion} - {self.trafico.src_ip}"


class ModelStatistics(models.Model):
    """Estadísticas del modelo de ML"""
    accuracy = models.FloatField()
    precision = models.FloatField()
    recall = models.FloatField()
    f1_score = models.FloatField()
    total_predictions = models.IntegerField(default=0)
    anomalies_detected = models.IntegerField(default=0)
    fecha_calculo = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'model_statistics'
        verbose_name = 'Estadística del Modelo'
        verbose_name_plural = 'Estadísticas del Modelo'
        ordering = ['-fecha_calculo']