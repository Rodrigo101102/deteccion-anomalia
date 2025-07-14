#!/usr/bin/env python3
"""
Sistema de Machine Learning para detección de anomalías
Implementa Isolation Forest para detección no supervisada
"""

import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from django.conf import settings


class PredictorAnomalias:
    """Predictor de anomalías usando Isolation Forest"""
    
    def __init__(self):
        self.modelo = None
        self.scaler = None
        self.features = [
            'src_port', 'dst_port', 'packet_size', 
            'duration', 'flow_bytes_per_sec', 'flow_packets_per_sec'
        ]
        self.cargar_modelo()
    
    def cargar_modelo(self):
        """Carga modelo pre-entrenado o crea uno nuevo"""
        model_path = os.path.join(settings.MEDIA_ROOT, 'models', 'anomaly_model.pkl')
        scaler_path = os.path.join(settings.MEDIA_ROOT, 'models', 'scaler.pkl')
        
        try:
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                self.modelo = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                logging.info("Modelo cargado exitosamente")
            else:
                self.entrenar_modelo_inicial()
        except Exception as e:
            logging.error(f"Error cargando modelo: {e}")
            self.entrenar_modelo_inicial()
    
    def entrenar_modelo_inicial(self):
        """Entrena modelo inicial con datos sintéticos"""
        try:
            from apps.traffic.models import TraficoRed
            
            # Obtener datos de entrenamiento si existen
            registros = list(TraficoRed.objects.all()[:10000])
            
            if len(registros) < 100:
                # Crear modelo con datos sintéticos
                datos_sinteticos = self.generar_datos_sinteticos()
                self.scaler = StandardScaler()
                X_scaled = self.scaler.fit_transform(datos_sinteticos)
                
                self.modelo = IsolationForest(contamination=0.1, random_state=42)
                self.modelo.fit(X_scaled)
            else:
                # Entrenar con datos reales
                df = self.convertir_a_dataframe(registros)
                self.entrenar_modelo(df)
            
            self.guardar_modelo()
            logging.info("Modelo inicial entrenado exitosamente")
            
        except Exception as e:
            logging.error(f"Error entrenando modelo inicial: {e}")
            # Modelo básico como fallback
            self.modelo = IsolationForest(contamination=0.1, random_state=42)
            self.scaler = StandardScaler()
    
    def generar_datos_sinteticos(self):
        """Genera datos sintéticos para inicialización"""
        np.random.seed(42)
        n_samples = 1000
        
        data = {
            'src_port': np.random.randint(1024, 65535, n_samples),
            'dst_port': np.random.randint(1, 65535, n_samples),
            'packet_size': np.random.exponential(1000, n_samples),
            'duration': np.random.exponential(1.0, n_samples),
            'flow_bytes_per_sec': np.random.exponential(10000, n_samples),
            'flow_packets_per_sec': np.random.exponential(100, n_samples)
        }
        
        return pd.DataFrame(data)
    
    def convertir_a_dataframe(self, registros):
        """Convierte registros Django a DataFrame"""
        data = []
        for registro in registros:
            data.append({
                'id': registro.id,
                'src_port': registro.src_port,
                'dst_port': registro.dst_port,
                'packet_size': registro.packet_size,
                'duration': registro.duration,
                'flow_bytes_per_sec': registro.flow_bytes_per_sec,
                'flow_packets_per_sec': registro.flow_packets_per_sec
            })
        
        return pd.DataFrame(data)
    
    def entrenar_modelo(self, df):
        """Entrena el modelo de detección de anomalías"""
        X = df[self.features]
        
        # Preprocesamiento
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Entrenar modelo
        self.modelo = IsolationForest(
            contamination=0.1,  # 10% de anomalías esperadas
            random_state=42,
            n_estimators=100
        )
        self.modelo.fit(X_scaled)
        
        logging.info("Modelo entrenado exitosamente")
    
    def predecir_anomalias(self, registros_ids=None):
        """Predice anomalías en registros no procesados"""
        try:
            from apps.traffic.models import TraficoRed
            from .models import ModeloPrediccion
            
            query = TraficoRed.objects.filter(procesado=False)
            
            if registros_ids:
                query = query.filter(id__in=registros_ids)
            
            registros = list(query)
            
            if not registros:
                logging.info("No hay registros para procesar")
                return 0
            
            df = self.convertir_a_dataframe(registros)
            X = df[self.features]
            
            # Preprocesar datos
            X_scaled = self.scaler.transform(X)
            
            # Realizar predicciones
            predicciones = self.modelo.predict(X_scaled)
            scores = self.modelo.decision_function(X_scaled)
            
            # Actualizar registros en base de datos
            registros_actualizados = 0
            for i, registro in enumerate(registros):
                # -1 es anomalía, 1 es normal en IsolationForest
                es_anomalia = predicciones[i] == -1
                score = scores[i]
                
                registro.label = 'ANOMALO' if es_anomalia else 'NORMAL'
                registro.procesado = True
                registro.save()
                
                # Registrar en tabla de predicciones
                ModeloPrediccion.objects.create(
                    trafico=registro,
                    prediccion=registro.label,
                    confidence_score=abs(score),
                    modelo_version='isolation_forest_v1'
                )
                
                registros_actualizados += 1
            
            logging.info(f"Procesados {registros_actualizados} registros")
            return registros_actualizados
            
        except Exception as e:
            logging.error(f"Error en predicción: {e}")
            return 0
    
    def guardar_modelo(self):
        """Guarda modelo y scaler entrenados"""
        try:
            models_dir = os.path.join(settings.MEDIA_ROOT, 'models')
            os.makedirs(models_dir, exist_ok=True)
            
            joblib.dump(self.modelo, os.path.join(models_dir, 'anomaly_model.pkl'))
            joblib.dump(self.scaler, os.path.join(models_dir, 'scaler.pkl'))
            
            logging.info("Modelo guardado exitosamente")
        except Exception as e:
            logging.error(f"Error guardando modelo: {e}")
    
    def estadisticas_prediccion(self):
        """Genera estadísticas de predicciones"""
        try:
            from apps.traffic.models import TraficoRed
            
            total = TraficoRed.objects.filter(procesado=True).count()
            anomalos = TraficoRed.objects.filter(label='ANOMALO').count()
            normales = TraficoRed.objects.filter(label='NORMAL').count()
            
            return {
                'total_procesados': total,
                'anomalos': anomalos,
                'normales': normales,
                'porcentaje_anomalos': (anomalos / total * 100) if total > 0 else 0
            }
        except Exception as e:
            logging.error(f"Error calculando estadísticas: {e}")
            return {'total_procesados': 0, 'anomalos': 0, 'normales': 0, 'porcentaje_anomalos': 0}