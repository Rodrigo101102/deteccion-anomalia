#!/usr/bin/env python3
"""
Script para procesar y limpiar archivos CSV generados por Flowmeter.
Normaliza datos y los prepara para inserción en la base de datos.
"""

import pandas as pd
import numpy as np
import os
import logging
from datetime import datetime
import re
import sys

# Configuración del logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/csv_processing.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class CSVProcessor:
    """Clase para procesar y limpiar archivos CSV de tráfico de red."""
    
    def __init__(self, input_dir='/tmp/csv_output', output_dir='/tmp/processed_csv'):
        """
        Inicializa el procesador de CSV.
        
        Args:
            input_dir: Directorio con archivos CSV de entrada
            output_dir: Directorio para archivos CSV procesados
        """
        self.input_dir = input_dir
        self.output_dir = output_dir
        
        # Crear directorio de salida si no existe
        os.makedirs(output_dir, exist_ok=True)
        
        # Mapeo de columnas estándar para la base de datos
        self.column_mapping = {
            'Src IP': 'src_ip',
            'Src Port': 'src_port',
            'Dst IP': 'dst_ip',
            'Dst Port': 'dst_port',
            'Protocol': 'protocol',
            'Flow Duration': 'duration',
            'Tot Fwd Pkts': 'total_fwd_packets',
            'Tot Bwd Pkts': 'total_backward_packets',
            'Flow Byts/s': 'flow_bytes_per_sec',
            'Flow Pkts/s': 'flow_packets_per_sec',
            'Flow IAT Mean': 'flow_iat_mean',
            'TotLen Fwd Pkts': 'packet_size',
            'Label': 'label'
        }
        
        # Columnas requeridas para la base de datos
        self.required_columns = [
            'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
            'packet_size', 'duration', 'flow_bytes_per_sec', 
            'flow_packets_per_sec', 'total_fwd_packets', 
            'total_backward_packets', 'flow_iat_mean'
        ]
    
    def validate_ip_address(self, ip):
        """Valida si una dirección IP es válida."""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, str(ip)):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def clean_ip_column(self, df, column):
        """Limpia y valida columnas de direcciones IP."""
        logger.info(f"Limpiando columna IP: {column}")
        
        # Convertir a string y eliminar espacios
        df[column] = df[column].astype(str).str.strip()
        
        # Filtrar IPs válidas
        valid_ips = df[column].apply(self.validate_ip_address)
        invalid_count = (~valid_ips).sum()
        
        if invalid_count > 0:
            logger.warning(f"Se encontraron {invalid_count} IPs inválidas en {column}")
            # Eliminar filas con IPs inválidas
            df = df[valid_ips]
        
        return df
    
    def clean_port_column(self, df, column):
        """Limpia y valida columnas de puertos."""
        logger.info(f"Limpiando columna de puerto: {column}")
        
        # Convertir a numérico
        df[column] = pd.to_numeric(df[column], errors='coerce')
        
        # Filtrar puertos válidos (1-65535)
        valid_ports = (df[column] >= 1) & (df[column] <= 65535)
        invalid_count = (~valid_ports).sum()
        
        if invalid_count > 0:
            logger.warning(f"Se encontraron {invalid_count} puertos inválidos en {column}")
            df = df[valid_ports]
        
        return df
    
    def clean_numeric_column(self, df, column):
        """Limpia columnas numéricas."""
        logger.info(f"Limpiando columna numérica: {column}")
        
        # Convertir a numérico
        df[column] = pd.to_numeric(df[column], errors='coerce')
        
        # Eliminar valores nulos
        null_count = df[column].isnull().sum()
        if null_count > 0:
            logger.warning(f"Se encontraron {null_count} valores nulos en {column}")
            df = df.dropna(subset=[column])
        
        # Eliminar valores infinitos
        inf_count = np.isinf(df[column]).sum()
        if inf_count > 0:
            logger.warning(f"Se encontraron {inf_count} valores infinitos en {column}")
            df = df[~np.isinf(df[column])]
        
        # Eliminar valores negativos para ciertas columnas
        if column in ['packet_size', 'duration', 'total_fwd_packets', 'total_backward_packets']:
            negative_count = (df[column] < 0).sum()
            if negative_count > 0:
                logger.warning(f"Se encontraron {negative_count} valores negativos en {column}")
                df = df[df[column] >= 0]
        
        return df
    
    def normalize_protocol(self, df):
        """Normaliza la columna de protocolo."""
        logger.info("Normalizando columna de protocolo")
        
        # Convertir a mayúsculas
        df['protocol'] = df['protocol'].astype(str).str.upper()
        
        # Mapear protocolos conocidos
        protocol_mapping = {
            '6': 'TCP',
            '17': 'UDP',
            '1': 'ICMP',
            'TRANSMISSION CONTROL PROTOCOL': 'TCP',
            'USER DATAGRAM PROTOCOL': 'UDP',
            'INTERNET CONTROL MESSAGE PROTOCOL': 'ICMP'
        }
        
        df['protocol'] = df['protocol'].replace(protocol_mapping)
        
        # Valores por defecto para protocolos no reconocidos
        unknown_protocols = ~df['protocol'].isin(['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'FTP', 'SSH'])
        df.loc[unknown_protocols, 'protocol'] = 'OTHER'
        
        return df
    
    def add_calculated_fields(self, df):
        """Agrega campos calculados necesarios para la base de datos."""
        logger.info("Agregando campos calculados")
        
        # Calcular flow_bytes_per_sec si no existe
        if 'flow_bytes_per_sec' not in df.columns or df['flow_bytes_per_sec'].isnull().all():
            df['flow_bytes_per_sec'] = np.where(
                df['duration'] > 0,
                df['packet_size'] / df['duration'],
                0
            )
        
        # Calcular flow_packets_per_sec si no existe
        if 'flow_packets_per_sec' not in df.columns or df['flow_packets_per_sec'].isnull().all():
            total_packets = df['total_fwd_packets'] + df['total_backward_packets']
            df['flow_packets_per_sec'] = np.where(
                df['duration'] > 0,
                total_packets / df['duration'],
                0
            )
        
        # Agregar timestamp de captura
        df['fecha_captura'] = datetime.now()
        
        # Agregar campos de estado
        df['procesado'] = False
        
        # Normalizar etiquetas
        if 'label' in df.columns:
            df['label'] = df['label'].astype(str).str.upper()
            label_mapping = {
                'BENIGN': 'NORMAL',
                'NORMAL': 'NORMAL',
                'ATTACK': 'ANOMALO',
                'MALICIOUS': 'ANOMALO',
                'ANOMALY': 'ANOMALO'
            }
            df['label'] = df['label'].replace(label_mapping)
            # Valores por defecto
            df['label'] = df['label'].fillna('PENDIENTE')
        else:
            df['label'] = 'PENDIENTE'
        
        return df
    
    def process_csv_file(self, csv_file_path):
        """
        Procesa un archivo CSV individual.
        
        Args:
            csv_file_path: Ruta al archivo CSV de entrada
            
        Returns:
            str: Ruta al archivo CSV procesado o None si hay error
        """
        try:
            logger.info(f"Procesando archivo: {csv_file_path}")
            
            # Leer CSV
            df = pd.read_csv(csv_file_path)
            initial_rows = len(df)
            logger.info(f"Filas iniciales: {initial_rows}")
            
            if df.empty:
                logger.warning("El archivo CSV está vacío")
                return None
            
            # Renombrar columnas según mapeo estándar
            df = df.rename(columns=self.column_mapping)
            
            # Verificar columnas requeridas
            missing_columns = set(self.required_columns) - set(df.columns)
            if missing_columns:
                logger.error(f"Faltan columnas requeridas: {missing_columns}")
                return None
            
            # Limpiar columnas de IP
            df = self.clean_ip_column(df, 'src_ip')
            df = self.clean_ip_column(df, 'dst_ip')
            
            # Limpiar columnas de puerto
            df = self.clean_port_column(df, 'src_port')
            df = self.clean_port_column(df, 'dst_port')
            
            # Limpiar columnas numéricas
            numeric_columns = [
                'packet_size', 'duration', 'flow_bytes_per_sec', 
                'flow_packets_per_sec', 'total_fwd_packets', 
                'total_backward_packets', 'flow_iat_mean'
            ]
            
            for col in numeric_columns:
                if col in df.columns:
                    df = self.clean_numeric_column(df, col)
            
            # Normalizar protocolo
            df = self.normalize_protocol(df)
            
            # Agregar campos calculados
            df = self.add_calculated_fields(df)
            
            # Eliminar duplicados
            df = df.drop_duplicates()
            
            final_rows = len(df)
            logger.info(f"Filas finales: {final_rows} (eliminadas: {initial_rows - final_rows})")
            
            if df.empty:
                logger.warning("No quedan datos después del procesamiento")
                return None
            
            # Guardar archivo procesado
            output_filename = f"processed_{os.path.basename(csv_file_path)}"
            output_path = os.path.join(self.output_dir, output_filename)
            
            # Seleccionar solo las columnas necesarias para la base de datos
            db_columns = self.required_columns + ['label', 'fecha_captura', 'procesado']
            df_output = df[db_columns]
            
            df_output.to_csv(output_path, index=False)
            logger.info(f"Archivo procesado guardado: {output_path}")
            
            return output_path
            
        except Exception as e:
            logger.error(f"Error procesando {csv_file_path}: {e}")
            return None
    
    def process_all_csv_files(self):
        """Procesa todos los archivos CSV en el directorio de entrada."""
        csv_files = [
            f for f in os.listdir(self.input_dir) 
            if f.endswith('.csv')
        ]
        
        if not csv_files:
            logger.info("No se encontraron archivos CSV para procesar")
            return []
        
        processed_files = []
        
        for csv_file in csv_files:
            input_path = os.path.join(self.input_dir, csv_file)
            output_path = self.process_csv_file(input_path)
            
            if output_path:
                processed_files.append(output_path)
        
        return processed_files
    
    def get_processing_summary(self, processed_files):
        """Genera un resumen del procesamiento."""
        summary = {
            'total_files': len(processed_files),
            'total_rows': 0,
            'files': []
        }
        
        for file_path in processed_files:
            try:
                df = pd.read_csv(file_path)
                file_info = {
                    'file': os.path.basename(file_path),
                    'rows': len(df),
                    'normal_traffic': len(df[df['label'] == 'NORMAL']),
                    'anomalous_traffic': len(df[df['label'] == 'ANOMALO']),
                    'pending_traffic': len(df[df['label'] == 'PENDIENTE'])
                }
                summary['files'].append(file_info)
                summary['total_rows'] += file_info['rows']
            except Exception as e:
                logger.error(f"Error obteniendo resumen de {file_path}: {e}")
        
        return summary

def main():
    """Función principal del script."""
    logger.info("=== Iniciando procesamiento de CSV ===")
    
    processor = CSVProcessor()
    
    try:
        # Procesar todos los archivos CSV
        processed_files = processor.process_all_csv_files()
        
        if processed_files:
            logger.info(f"\nArchivos procesados exitosamente: {len(processed_files)}")
            
            # Mostrar resumen
            summary = processor.get_processing_summary(processed_files)
            logger.info(f"Total de filas procesadas: {summary['total_rows']}")
            
            for file_info in summary['files']:
                logger.info(f"  {file_info['file']}: {file_info['rows']} filas")
                logger.info(f"    Normal: {file_info['normal_traffic']}, "
                           f"Anómalo: {file_info['anomalous_traffic']}, "
                           f"Pendiente: {file_info['pending_traffic']}")
        else:
            logger.warning("No se procesaron archivos CSV")
        
        logger.info("=== Procesamiento completado ===")
        
    except Exception as e:
        logger.error(f"Error en procesamiento: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()