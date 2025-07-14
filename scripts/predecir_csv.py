#!/usr/bin/env python3
"""
Script para predicción de anomalías usando Machine Learning.
Carga un modelo pre-entrenado y clasifica el tráfico de red.
"""

import pandas as pd
import numpy as np
import joblib
import logging
from datetime import datetime
import os
import sys
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import warnings

warnings.filterwarnings('ignore')

# Configuración del logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/prediction.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class AnomalyPredictor:
    """Clase para predicción de anomalías en tráfico de red."""
    
    def __init__(self, model_dir='/tmp/models'):
        """
        Inicializa el predictor de anomalías.
        
        Args:
            model_dir: Directorio donde se almacenan los modelos
        """
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.feature_columns = [
            'src_port', 'dst_port', 'packet_size', 'duration',
            'flow_bytes_per_sec', 'flow_packets_per_sec',
            'total_fwd_packets', 'total_backward_packets', 'flow_iat_mean'
        ]
        
        # Crear directorio de modelos si no existe
        os.makedirs(model_dir, exist_ok=True)
        
        # Rutas de archivos del modelo
        self.model_path = os.path.join(model_dir, 'anomaly_model.joblib')
        self.scaler_path = os.path.join(model_dir, 'scaler.joblib')
    
    def create_simple_model(self):
        """Crea un modelo simple de detección de anomalías."""
        logger.info("Creando modelo simple de detección de anomalías")
        
        # Usar Isolation Forest como modelo base
        self.model = IsolationForest(
            contamination=0.1,  # 10% de anomalías esperadas
            random_state=42,
            n_estimators=100
        )
        
        self.scaler = StandardScaler()
        
        # Generar datos sintéticos para entrenar el modelo base
        self._generate_training_data()
        
        return True
    
    def _generate_training_data(self):
        """Genera datos sintéticos para entrenar el modelo base."""
        logger.info("Generando datos sintéticos para entrenamiento")
        
        np.random.seed(42)
        n_samples = 1000
        
        # Generar datos normales
        normal_data = {
            'src_port': np.random.randint(1024, 65535, n_samples),
            'dst_port': np.random.choice([80, 443, 22, 21, 25], n_samples),
            'packet_size': np.random.normal(800, 200, n_samples),
            'duration': np.random.exponential(5, n_samples),
            'flow_bytes_per_sec': np.random.lognormal(8, 2, n_samples),
            'flow_packets_per_sec': np.random.lognormal(2, 1, n_samples),
            'total_fwd_packets': np.random.poisson(10, n_samples),
            'total_backward_packets': np.random.poisson(8, n_samples),
            'flow_iat_mean': np.random.exponential(0.1, n_samples)
        }
        
        # Generar algunos datos anómalos
        n_anomalies = 100
        anomalous_data = {
            'src_port': np.random.randint(1, 1024, n_anomalies),  # Puertos privilegiados
            'dst_port': np.random.randint(1, 65535, n_anomalies),  # Puertos aleatorios
            'packet_size': np.random.uniform(10000, 50000, n_anomalies),  # Paquetes muy grandes
            'duration': np.random.uniform(100, 1000, n_anomalies),  # Duraciones muy largas
            'flow_bytes_per_sec': np.random.uniform(1000000, 10000000, n_anomalies),  # Muy alto
            'flow_packets_per_sec': np.random.uniform(1000, 10000, n_anomalies),  # Muy alto
            'total_fwd_packets': np.random.uniform(1000, 10000, n_anomalies),  # Muy alto
            'total_backward_packets': np.random.uniform(1000, 10000, n_anomalies),  # Muy alto
            'flow_iat_mean': np.random.uniform(10, 100, n_anomalies)  # Muy alto
        }
        
        # Combinar datos
        training_data = {}
        for feature in self.feature_columns:
            training_data[feature] = np.concatenate([
                normal_data[feature],
                anomalous_data[feature]
            ])
        
        df_training = pd.DataFrame(training_data)
        
        # Limpiar datos
        df_training = df_training.replace([np.inf, -np.inf], np.nan)
        df_training = df_training.fillna(0)
        df_training = df_training[df_training >= 0]  # Solo valores positivos
        
        # Normalizar datos
        X_scaled = self.scaler.fit_transform(df_training[self.feature_columns])
        
        # Entrenar modelo
        self.model.fit(X_scaled)
        
        logger.info(f"Modelo entrenado con {len(df_training)} muestras")
    
    def save_model(self):
        """Guarda el modelo y el scaler entrenados."""
        try:
            if self.model is not None:
                joblib.dump(self.model, self.model_path)
                logger.info(f"Modelo guardado: {self.model_path}")
            
            if self.scaler is not None:
                joblib.dump(self.scaler, self.scaler_path)
                logger.info(f"Scaler guardado: {self.scaler_path}")
            
            return True
        except Exception as e:
            logger.error(f"Error guardando modelo: {e}")
            return False
    
    def load_model(self):
        """Carga el modelo y scaler pre-entrenados."""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                logger.info(f"Modelo cargado: {self.model_path}")
            else:
                logger.info("No se encontró modelo pre-entrenado, creando nuevo modelo")
                return self.create_simple_model()
            
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
                logger.info(f"Scaler cargado: {self.scaler_path}")
            else:
                logger.warning("No se encontró scaler, creando nuevo")
                self.scaler = StandardScaler()
            
            return True
            
        except Exception as e:
            logger.error(f"Error cargando modelo: {e}")
            return self.create_simple_model()
    
    def preprocess_data(self, df):
        """Preprocesa los datos para predicción."""
        logger.info("Preprocesando datos para predicción")
        
        # Verificar que existan las columnas necesarias
        missing_cols = set(self.feature_columns) - set(df.columns)
        if missing_cols:
            logger.error(f"Faltan columnas requeridas: {missing_cols}")
            return None
        
        # Seleccionar solo las columnas de características
        X = df[self.feature_columns].copy()
        
        # Limpiar datos
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0)
        
        # Asegurar que todos los valores sean positivos para ciertas columnas
        positive_columns = ['packet_size', 'duration', 'total_fwd_packets', 'total_backward_packets']
        for col in positive_columns:
            if col in X.columns:
                X[col] = X[col].abs()
        
        # Escalar datos
        try:
            X_scaled = self.scaler.transform(X)
            return X_scaled
        except Exception as e:
            logger.error(f"Error en escalado de datos: {e}")
            # Si falla, usar el scaler en modo fit_transform
            X_scaled = self.scaler.fit_transform(X)
            return X_scaled
    
    def predict_anomalies(self, df):
        """
        Predice anomalías en el tráfico de red.
        
        Args:
            df: DataFrame con datos de tráfico
            
        Returns:
            DataFrame con predicciones agregadas
        """
        logger.info(f"Prediciendo anomalías para {len(df)} registros")
        
        if self.model is None:
            logger.error("Modelo no cargado")
            return df
        
        # Preprocesar datos
        X_scaled = self.preprocess_data(df)
        if X_scaled is None:
            return df
        
        try:
            # Realizar predicciones
            predictions = self.model.predict(X_scaled)
            scores = self.model.decision_function(X_scaled)
            
            # Convertir predicciones (-1: anomalía, 1: normal)
            df['prediction'] = predictions
            df['anomaly_score'] = scores
            
            # Mapear a etiquetas legibles
            df['label'] = df['prediction'].map({1: 'NORMAL', -1: 'ANOMALO'})
            
            # Calcular puntuación de confianza (0-1)
            # Normalizar scores a rango 0-1
            min_score = scores.min()
            max_score = scores.max()
            if max_score > min_score:
                confidence = (scores - min_score) / (max_score - min_score)
            else:
                confidence = np.ones(len(scores)) * 0.5
            
            # Para anomalías, invertir la confianza
            df['confidence_score'] = np.where(
                df['prediction'] == -1,
                1 - confidence,  # Anomalías: menor score = mayor confianza
                confidence       # Normal: mayor score = mayor confianza
            )
            
            # Marcar como procesado
            df['procesado'] = True
            
            # Estadísticas
            anomalies = (predictions == -1).sum()
            normal = (predictions == 1).sum()
            
            logger.info(f"Predicciones completadas:")
            logger.info(f"  Normal: {normal} ({normal/len(df)*100:.1f}%)")
            logger.info(f"  Anómalo: {anomalies} ({anomalies/len(df)*100:.1f}%)")
            
            return df
            
        except Exception as e:
            logger.error(f"Error en predicción: {e}")
            return df
    
    def predict_csv_file(self, csv_file_path, output_path=None):
        """
        Procesa un archivo CSV y genera predicciones.
        
        Args:
            csv_file_path: Ruta al archivo CSV de entrada
            output_path: Ruta para guardar resultados (opcional)
            
        Returns:
            str: Ruta al archivo con predicciones
        """
        try:
            logger.info(f"Procesando archivo: {csv_file_path}")
            
            # Leer CSV
            df = pd.read_csv(csv_file_path)
            
            if df.empty:
                logger.warning("El archivo CSV está vacío")
                return None
            
            # Realizar predicciones
            df_with_predictions = self.predict_anomalies(df)
            
            # Determinar ruta de salida
            if output_path is None:
                base_name = os.path.splitext(os.path.basename(csv_file_path))[0]
                output_path = os.path.join(
                    os.path.dirname(csv_file_path),
                    f"{base_name}_predicted.csv"
                )
            
            # Guardar resultados
            df_with_predictions.to_csv(output_path, index=False)
            logger.info(f"Predicciones guardadas: {output_path}")
            
            return output_path
            
        except Exception as e:
            logger.error(f"Error procesando {csv_file_path}: {e}")
            return None
    
    def batch_predict(self, input_dir='/tmp/processed_csv'):
        """Procesa todos los archivos CSV en un directorio."""
        csv_files = [
            f for f in os.listdir(input_dir)
            if f.endswith('.csv') and not f.endswith('_predicted.csv')
        ]
        
        if not csv_files:
            logger.info("No se encontraron archivos CSV para procesar")
            return []
        
        predicted_files = []
        
        for csv_file in csv_files:
            input_path = os.path.join(input_dir, csv_file)
            output_path = self.predict_csv_file(input_path)
            
            if output_path:
                predicted_files.append(output_path)
        
        return predicted_files

def main():
    """Función principal del script."""
    logger.info("=== Iniciando predicción de anomalías ===")
    
    # Inicializar predictor
    predictor = AnomalyPredictor()
    
    try:
        # Cargar o crear modelo
        if not predictor.load_model():
            logger.error("No se pudo cargar o crear el modelo")
            sys.exit(1)
        
        # Guardar modelo si es nuevo
        predictor.save_model()
        
        # Procesar archivos CSV
        predicted_files = predictor.batch_predict()
        
        if predicted_files:
            logger.info(f"\nArchivos procesados: {len(predicted_files)}")
            for file_path in predicted_files:
                logger.info(f"  - {file_path}")
        else:
            logger.info("No se procesaron archivos")
        
        logger.info("=== Predicción completada ===")
        
    except Exception as e:
        logger.error(f"Error en predicción: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()