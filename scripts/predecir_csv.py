#!/usr/bin/env python3
"""
Sistema de predicción de anomalías usando Machine Learning
Procesa registros de tráfico y predice anomalías
"""

import os
import sys
import django
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import logging
from pathlib import Path
from datetime import datetime
import argparse

# Añadir el directorio raíz al path para importar Django
sys.path.append(str(Path(__file__).parent.parent))

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'anomalia_detection.settings.development')

try:
    django.setup()
    from apps.traffic.models import TraficoRed
    from apps.prediction.models import ModeloPrediccion
    from apps.core.models import SystemConfiguration
    from apps.core.utils import create_system_alert
    from apps.core.signals import model_retrained
    DJANGO_AVAILABLE = True
except ImportError as e:
    print(f"Django no disponible: {e}")
    DJANGO_AVAILABLE = False

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/ml_predictor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PredictorAnomalias:
    """Sistema de predicción de anomalías de tráfico de red"""
    
    def __init__(self, model_dir=None):
        self.model_dir = model_dir or '/media/models/'
        self.model = None
        self.scaler = None
        
        # Características utilizadas para predicción
        self.features = [
            'src_port', 'dst_port', 'packet_size', 
            'duration', 'flow_bytes_per_sec', 'flow_packets_per_sec',
            'total_fwd_packets', 'total_backward_packets',
            'fwd_packet_length_mean', 'fwd_packet_length_std'
        ]
        
        # Crear directorio de modelos
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Cargar modelo existente
        self.cargar_modelo()
    
    def cargar_modelo(self):
        """Carga modelo pre-entrenado o crea uno nuevo"""
        model_path = os.path.join(self.model_dir, 'anomaly_model.pkl')
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        
        try:
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                logger.info("Modelo cargado exitosamente")
                return True
            else:
                logger.warning("Modelo no encontrado, se creará uno nuevo")
                return self.entrenar_modelo_inicial()
        except Exception as e:
            logger.error(f"Error cargando modelo: {e}")
            return self.entrenar_modelo_inicial()
    
    def entrenar_modelo_inicial(self):
        """Entrena modelo inicial con datos disponibles"""
        try:
            logger.info("Entrenando modelo inicial...")
            
            if DJANGO_AVAILABLE:
                # Obtener datos de entrenamiento
                registros = TraficoRed.objects.all()[:10000]  # Primeros 10k registros
                
                if len(registros) < 100:
                    logger.warning("Pocos datos disponibles, creando modelo sintético")
                    return self.crear_modelo_sintetico()
                
                # Convertir a DataFrame
                df = self.convertir_a_dataframe(registros)
                return self.entrenar_modelo(df)
            else:
                return self.crear_modelo_sintetico()
                
        except Exception as e:
            logger.error(f"Error entrenando modelo inicial: {e}")
            return self.crear_modelo_sintetico()
    
    def crear_modelo_sintetico(self):
        """Crea modelo con datos sintéticos para inicialización"""
        logger.info("Creando modelo con datos sintéticos...")
        
        try:
            # Generar datos sintéticos
            np.random.seed(42)
            n_samples = 1000
            
            data = {
                'src_port': np.random.randint(1024, 65535, n_samples),
                'dst_port': np.random.randint(1, 65535, n_samples),
                'packet_size': np.random.exponential(1000, n_samples),
                'duration': np.random.exponential(1.0, n_samples),
                'flow_bytes_per_sec': np.random.exponential(10000, n_samples),
                'flow_packets_per_sec': np.random.exponential(100, n_samples),
                'total_fwd_packets': np.random.poisson(10, n_samples),
                'total_backward_packets': np.random.poisson(5, n_samples),
                'fwd_packet_length_mean': np.random.normal(800, 200, n_samples),
                'fwd_packet_length_std': np.random.exponential(100, n_samples)
            }
            
            df = pd.DataFrame(data)
            
            # Entrenar modelo
            return self.entrenar_modelo(df)
            
        except Exception as e:
            logger.error(f"Error creando modelo sintético: {e}")
            return False
    
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
                'flow_packets_per_sec': registro.flow_packets_per_sec,
                'total_fwd_packets': registro.total_fwd_packets,
                'total_backward_packets': registro.total_backward_packets,
                'fwd_packet_length_mean': registro.fwd_packet_length_mean,
                'fwd_packet_length_std': registro.fwd_packet_length_std
            })
        
        return pd.DataFrame(data)
    
    def preprocesar_datos(self, df):
        """Preprocesa datos para entrenamiento/predicción"""
        # Seleccionar características
        X = df[self.features].copy()
        
        # Manejar valores faltantes
        X = X.fillna(0)
        
        # Manejar valores infinitos
        X = X.replace([np.inf, -np.inf], 0)
        
        # Validar rangos
        X['src_port'] = X['src_port'].clip(0, 65535)
        X['dst_port'] = X['dst_port'].clip(0, 65535)
        X['packet_size'] = X['packet_size'].clip(0, 65535)
        X['duration'] = X['duration'].clip(0, 3600)
        
        return X
    
    def entrenar_modelo(self, df):
        """Entrena el modelo de detección de anomalías"""
        try:
            logger.info(f"Entrenando modelo con {len(df)} registros...")
            
            # Preprocesar datos
            X = self.preprocesar_datos(df)
            
            if X.empty:
                raise Exception("No hay datos válidos para entrenamiento")
            
            # Configurar parámetros del modelo
            contamination = 0.1  # 10% de anomalías esperadas
            if DJANGO_AVAILABLE:
                try:
                    config = SystemConfiguration.get_current_config()
                    contamination = config.ml_contamination
                except:
                    pass
            
            # Normalizar datos
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Entrenar modelo
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
                bootstrap=False,
                n_jobs=-1
            )
            
            self.model.fit(X_scaled)
            
            # Guardar modelo
            self.guardar_modelo()
            
            # Evaluar modelo
            scores = self.model.decision_function(X_scaled)
            predictions = self.model.predict(X_scaled)
            
            anomalias = np.sum(predictions == -1)
            normales = np.sum(predictions == 1)
            
            logger.info(f"Modelo entrenado exitosamente:")
            logger.info(f"- Registros procesados: {len(X)}")
            logger.info(f"- Anomalías detectadas: {anomalias} ({anomalias/len(X)*100:.1f}%)")
            logger.info(f"- Normales: {normales} ({normales/len(X)*100:.1f}%)")
            
            # Emitir señal de modelo reentrenado
            if DJANGO_AVAILABLE:
                try:
                    model_retrained.send(
                        sender=self.__class__,
                        model_info={
                            'timestamp': datetime.now().isoformat(),
                            'samples_trained': len(X),
                            'contamination': contamination,
                            'anomalies_detected': int(anomalias),
                            'model_type': 'IsolationForest'
                        }
                    )
                except:
                    pass
            
            return True
            
        except Exception as e:
            logger.error(f"Error entrenando modelo: {e}")
            return False
    
    def predecir_anomalias(self, registros_ids=None, batch_size=1000):
        """Predice anomalías en registros no procesados"""
        if not self.model or not self.scaler:
            logger.error("Modelo no disponible")
            return 0
        
        if not DJANGO_AVAILABLE:
            logger.error("Django no disponible")
            return 0
        
        try:
            # Obtener registros no procesados
            query = TraficoRed.objects.filter(procesado=False)
            
            if registros_ids:
                query = query.filter(id__in=registros_ids)
            
            registros = list(query)
            
            if not registros:
                logger.info("No hay registros para procesar")
                return 0
            
            logger.info(f"Procesando {len(registros)} registros...")
            
            # Convertir a DataFrame
            df = self.convertir_a_dataframe(registros)
            
            # Preprocesar datos
            X = self.preprocesar_datos(df)
            
            if X.empty:
                logger.warning("No hay datos válidos para predicción")
                return 0
            
            # Normalizar datos
            X_scaled = self.scaler.transform(X)
            
            # Realizar predicciones
            predictions = self.model.predict(X_scaled)
            scores = self.model.decision_function(X_scaled)
            
            # Procesar en lotes para evitar problemas de memoria
            registros_actualizados = 0
            predicciones_creadas = 0
            
            for i in range(0, len(registros), batch_size):
                batch_registros = registros[i:i+batch_size]
                batch_predictions = predictions[i:i+batch_size]
                batch_scores = scores[i:i+batch_size]
                
                # Actualizar registros en lote
                batch_updates = []
                batch_predicciones = []
                
                for j, registro in enumerate(batch_registros):
                    # -1 es anomalía, 1 es normal en IsolationForest
                    es_anomalia = batch_predictions[j] == -1
                    score = batch_scores[j]
                    confidence = abs(score)  # Convertir a valor positivo
                    
                    # Actualizar registro
                    registro.label = 'ANOMALO' if es_anomalia else 'NORMAL'
                    registro.confidence_score = confidence
                    registro.procesado = True
                    batch_updates.append(registro)
                    
                    # Crear predicción
                    batch_predicciones.append(ModeloPrediccion(
                        trafico=registro,
                        prediccion=registro.label,
                        confidence_score=confidence,
                        modelo_version='isolation_forest_v1',
                        fecha_prediccion=datetime.now()
                    ))
                
                # Actualizar en lote
                TraficoRed.objects.bulk_update(
                    batch_updates, 
                    ['label', 'confidence_score', 'procesado']
                )
                
                # Crear predicciones en lote
                ModeloPrediccion.objects.bulk_create(batch_predicciones)
                
                registros_actualizados += len(batch_updates)
                predicciones_creadas += len(batch_predicciones)
                
                logger.debug(f"Lote {i//batch_size + 1}: {len(batch_updates)} registros procesados")
            
            # Estadísticas finales
            anomalias = np.sum(predictions == -1)
            normales = np.sum(predictions == 1)
            
            logger.info(f"Predicción completada:")
            logger.info(f"- Registros procesados: {registros_actualizados}")
            logger.info(f"- Anomalías detectadas: {anomalias} ({anomalias/len(predictions)*100:.1f}%)")
            logger.info(f"- Normales: {normales} ({normales/len(predictions)*100:.1f}%)")
            logger.info(f"- Predicciones creadas: {predicciones_creadas}")
            
            # Crear alerta si hay muchas anomalías
            if anomalias > len(predictions) * 0.2:  # Más del 20%
                create_system_alert(
                    title='Alto número de anomalías detectadas',
                    description=f'Se detectaron {anomalias} anomalías de {len(predictions)} registros procesados ({anomalias/len(predictions)*100:.1f}%)',
                    severity='medium',
                    alert_type='high_anomalies',
                    alert_data={
                        'total_processed': len(predictions),
                        'anomalies_detected': int(anomalias),
                        'anomaly_percentage': float(anomalias/len(predictions)*100)
                    }
                )
            
            return registros_actualizados
            
        except Exception as e:
            logger.error(f"Error en predicción: {e}")
            return 0
    
    def guardar_modelo(self):
        """Guarda modelo y scaler entrenados"""
        try:
            model_path = os.path.join(self.model_dir, 'anomaly_model.pkl')
            scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
            metadata_path = os.path.join(self.model_dir, 'model_metadata.json')
            
            # Guardar modelo y scaler
            joblib.dump(self.model, model_path)
            joblib.dump(self.scaler, scaler_path)
            
            # Guardar metadatos
            import json
            metadata = {
                'model_type': 'IsolationForest',
                'features': self.features,
                'trained_at': datetime.now().isoformat(),
                'sklearn_version': joblib.__version__
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("Modelo guardado exitosamente")
            
        except Exception as e:
            logger.error(f"Error guardando modelo: {e}")
    
    def estadisticas_prediccion(self):
        """Genera estadísticas de predicciones"""
        if not DJANGO_AVAILABLE:
            return {}
        
        try:
            from django.db.models import Count
            
            total = TraficoRed.objects.filter(procesado=True).count()
            anomalos = TraficoRed.objects.filter(label='ANOMALO').count()
            normales = TraficoRed.objects.filter(label='NORMAL').count()
            
            # Estadísticas por confianza
            alta_confianza = TraficoRed.objects.filter(
                procesado=True,
                confidence_score__gte=0.8
            ).count()
            
            # Predicciones recientes
            predicciones_recientes = ModeloPrediccion.objects.count()
            
            stats = {
                'total_procesados': total,
                'anomalos': anomalos,
                'normales': normales,
                'porcentaje_anomalos': (anomalos / total * 100) if total > 0 else 0,
                'alta_confianza': alta_confianza,
                'predicciones_realizadas': predicciones_recientes,
                'modelo_disponible': self.model is not None
            }
            
            logger.info(f"Estadísticas de predicción: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {}
    
    def validar_modelo(self):
        """Valida el modelo actual"""
        if not self.model or not self.scaler:
            return False
        
        try:
            # Crear datos de prueba
            test_data = pd.DataFrame({
                'src_port': [80, 443, 22],
                'dst_port': [12345, 54321, 8080],
                'packet_size': [1000, 1500, 500],
                'duration': [1.0, 2.0, 0.5],
                'flow_bytes_per_sec': [1000, 750, 1000],
                'flow_packets_per_sec': [1, 0.5, 2],
                'total_fwd_packets': [1, 1, 1],
                'total_backward_packets': [0, 0, 0],
                'fwd_packet_length_mean': [1000, 1500, 500],
                'fwd_packet_length_std': [0, 0, 0]
            })
            
            # Hacer predicción de prueba
            X = self.preprocesar_datos(test_data)
            X_scaled = self.scaler.transform(X)
            predictions = self.model.predict(X_scaled)
            
            logger.info("Modelo validado exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"Error validando modelo: {e}")
            return False


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Predictor de anomalías de tráfico de red')
    parser.add_argument('--model-dir', '-m', help='Directorio de modelos')
    parser.add_argument('--train', '-t', action='store_true', help='Entrenar nuevo modelo')
    parser.add_argument('--predict', '-p', action='store_true', help='Realizar predicciones')
    parser.add_argument('--stats', '-s', action='store_true', help='Mostrar estadísticas')
    parser.add_argument('--validate', '-v', action='store_true', help='Validar modelo')
    parser.add_argument('--batch-size', '-b', type=int, default=1000, help='Tamaño de lote')
    
    args = parser.parse_args()
    
    # Crear predictor
    predictor = PredictorAnomalias(model_dir=args.model_dir)
    
    try:
        if args.stats:
            predictor.estadisticas_prediccion()
            return
        
        if args.validate:
            if predictor.validar_modelo():
                logger.info("Modelo válido")
            else:
                logger.error("Modelo inválido")
            return
        
        if args.train:
            if predictor.entrenar_modelo_inicial():
                logger.info("Entrenamiento completado")
            else:
                logger.error("Error en entrenamiento")
            return
        
        if args.predict or not any([args.train, args.stats, args.validate]):
            registros_procesados = predictor.predecir_anomalias(batch_size=args.batch_size)
            logger.info(f"Predicción completada: {registros_procesados} registros procesados")
            return
            
    except Exception as e:
        logger.error(f"Error en ejecución: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()