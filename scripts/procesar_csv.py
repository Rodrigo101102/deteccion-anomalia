#!/usr/bin/env python3
"""
Procesamiento y limpieza de archivos CSV generados por Flowmeter
Normaliza datos y prepara para inserción en base de datos
"""

import pandas as pd
import numpy as np
import os
import sys
import logging
from datetime import datetime
from pathlib import Path
import django
import argparse

# Añadir el directorio raíz al path para importar Django
sys.path.append(str(Path(__file__).parent.parent))

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'anomalia_detection.settings.development')

try:
    django.setup()
    from apps.traffic.models import TraficoRed
    from apps.core.models import SystemConfiguration
    from apps.core.utils import create_system_alert
    DJANGO_AVAILABLE = True
except ImportError as e:
    print(f"Django no disponible: {e}")
    DJANGO_AVAILABLE = False

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/csv_processor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ProcesadorCSV:
    """Clase para procesar y limpiar archivos CSV de tráfico de red"""
    
    def __init__(self, csv_dir=None, batch_size=1000):
        self.csv_dir = csv_dir or '/media/csv_files/'
        self.processed_dir = os.path.join(self.csv_dir, 'processed')
        self.error_dir = os.path.join(self.csv_dir, 'errors')
        self.batch_size = batch_size
        
        # Mapeo de columnas estándar
        self.columns_mapping = {
            'src_ip': 'src_ip',
            'dst_ip': 'dst_ip', 
            'src_port': 'src_port',
            'dst_port': 'dst_port',
            'protocol': 'protocol',
            'packet_size': 'packet_size',
            'relative_time': 'duration',
            'tcp_length': 'tcp_length',
            'udp_length': 'udp_length',
            'ip_length': 'ip_length',
            'tcp_flags': 'tcp_flags',
            'protocols': 'protocol'
        }
        
        # Crear directorios necesarios
        self.crear_directorios()
        
    def crear_directorios(self):
        """Crea directorios necesarios"""
        for directory in [self.csv_dir, self.processed_dir, self.error_dir]:
            os.makedirs(directory, exist_ok=True)
            
    def listar_archivos_csv(self):
        """Lista archivos CSV pendientes de procesar"""
        try:
            archivos = [
                f for f in os.listdir(self.csv_dir) 
                if f.endswith('.csv') and os.path.isfile(os.path.join(self.csv_dir, f))
            ]
            return sorted(archivos)
        except Exception as e:
            logger.error(f"Error listando archivos CSV: {e}")
            return []
    
    def leer_csv(self, csv_file):
        """Lee archivo CSV con manejo de errores"""
        try:
            logger.info(f"Leyendo archivo: {csv_file}")
            
            # Intentar leer con diferentes encodings
            encodings = ['utf-8', 'latin1', 'cp1252']
            df = None
            
            for encoding in encodings:
                try:
                    df = pd.read_csv(csv_file, encoding=encoding, low_memory=False)
                    logger.debug(f"Archivo leído con encoding: {encoding}")
                    break
                except UnicodeDecodeError:
                    continue
            
            if df is None:
                raise Exception("No se pudo leer el archivo con ningún encoding")
            
            logger.info(f"CSV leído: {len(df)} filas, {len(df.columns)} columnas")
            return df
            
        except Exception as e:
            logger.error(f"Error leyendo CSV {csv_file}: {e}")
            raise
    
    def mapear_columnas(self, df):
        """Mapea columnas del CSV a nombres estándar"""
        logger.debug("Mapeando columnas...")
        
        # Mostrar columnas disponibles
        logger.debug(f"Columnas disponibles: {list(df.columns)}")
        
        # Crear mapeo dinámico basado en las columnas disponibles
        column_map = {}
        for csv_col in df.columns:
            csv_col_lower = csv_col.lower().strip()
            
            # Mapeo directo
            if csv_col_lower in self.columns_mapping:
                column_map[csv_col] = self.columns_mapping[csv_col_lower]
            # Mapeo por similitud
            elif 'src' in csv_col_lower and 'ip' in csv_col_lower:
                column_map[csv_col] = 'src_ip'
            elif 'dst' in csv_col_lower and 'ip' in csv_col_lower:
                column_map[csv_col] = 'dst_ip'
            elif 'src' in csv_col_lower and 'port' in csv_col_lower:
                column_map[csv_col] = 'src_port'
            elif 'dst' in csv_col_lower and 'port' in csv_col_lower:
                column_map[csv_col] = 'dst_port'
            elif 'protocol' in csv_col_lower:
                column_map[csv_col] = 'protocol'
            elif 'size' in csv_col_lower or 'len' in csv_col_lower:
                column_map[csv_col] = 'packet_size'
            elif 'time' in csv_col_lower or 'duration' in csv_col_lower:
                column_map[csv_col] = 'duration'
        
        # Renombrar columnas
        df_renamed = df.rename(columns=column_map)
        logger.debug(f"Columnas mapeadas: {column_map}")
        
        return df_renamed
    
    def limpiar_datos(self, df):
        """Limpia y normaliza los datos"""
        logger.info("Iniciando limpieza de datos...")
        filas_originales = len(df)
        
        # 1. Eliminar filas completamente vacías
        df = df.dropna(how='all')
        logger.debug(f"Filas después de eliminar vacías: {len(df)}")
        
        # 2. Validar y limpiar IPs
        df = self.limpiar_ips(df)
        
        # 3. Validar y limpiar puertos
        df = self.limpiar_puertos(df)
        
        # 4. Limpiar protocolo
        df = self.limpiar_protocolo(df)
        
        # 5. Limpiar métricas numéricas
        df = self.limpiar_metricas(df)
        
        # 6. Calcular campos derivados
        df = self.calcular_campos_derivados(df)
        
        # 7. Validación final
        df = self.validacion_final(df)
        
        filas_finales = len(df)
        logger.info(f"Limpieza completada: {filas_originales} -> {filas_finales} filas ({filas_finales/filas_originales*100:.1f}% conservadas)")
        
        return df
    
    def limpiar_ips(self, df):
        """Limpia y valida direcciones IP"""
        logger.debug("Limpiando direcciones IP...")
        
        # Función para validar IP
        def validate_ip(ip_str):
            if pd.isna(ip_str) or ip_str == '':
                return '0.0.0.0'
            
            try:
                import ipaddress
                ip = ipaddress.ip_address(str(ip_str).strip())
                return str(ip)
            except:
                return '0.0.0.0'
        
        # Limpiar IPs origen y destino
        if 'src_ip' in df.columns:
            df['src_ip'] = df['src_ip'].apply(validate_ip)
        else:
            df['src_ip'] = '0.0.0.0'
            
        if 'dst_ip' in df.columns:
            df['dst_ip'] = df['dst_ip'].apply(validate_ip)
        else:
            df['dst_ip'] = '0.0.0.0'
        
        # Eliminar filas donde ambas IPs son inválidas
        df = df[~((df['src_ip'] == '0.0.0.0') & (df['dst_ip'] == '0.0.0.0'))]
        
        return df
    
    def limpiar_puertos(self, df):
        """Limpia y valida puertos"""
        logger.debug("Limpiando puertos...")
        
        def clean_port(port_val):
            if pd.isna(port_val) or port_val == '':
                return 0
            
            try:
                port = int(float(str(port_val)))
                return port if 0 <= port <= 65535 else 0
            except:
                return 0
        
        # Limpiar puertos
        if 'src_port' in df.columns:
            df['src_port'] = df['src_port'].apply(clean_port)
        else:
            df['src_port'] = 0
            
        if 'dst_port' in df.columns:
            df['dst_port'] = df['dst_port'].apply(clean_port)
        else:
            df['dst_port'] = 0
        
        # Si no hay puertos, intentar obtener de columnas TCP/UDP separadas
        if 'src_port_udp' in df.columns or 'dst_port_udp' in df.columns:
            df['src_port'] = df['src_port'].fillna(0) + df.get('src_port_udp', 0).fillna(0)
            df['dst_port'] = df['dst_port'].fillna(0) + df.get('dst_port_udp', 0).fillna(0)
        
        return df
    
    def limpiar_protocolo(self, df):
        """Limpia campo de protocolo"""
        logger.debug("Limpiando protocolo...")
        
        def normalize_protocol(protocol_val):
            if pd.isna(protocol_val) or protocol_val == '':
                return 'OTHER'
            
            protocol_str = str(protocol_val).upper().strip()
            
            # Mapeo de protocolos
            if 'TCP' in protocol_str:
                return 'TCP'
            elif 'UDP' in protocol_str:
                return 'UDP'
            elif 'ICMP' in protocol_str:
                return 'ICMP'
            elif 'HTTP' in protocol_str and 'HTTPS' not in protocol_str:
                return 'HTTP'
            elif 'HTTPS' in protocol_str or 'SSL' in protocol_str or 'TLS' in protocol_str:
                return 'HTTPS'
            elif 'DNS' in protocol_str:
                return 'DNS'
            elif 'SSH' in protocol_str:
                return 'SSH'
            elif 'FTP' in protocol_str:
                return 'FTP'
            elif 'SMTP' in protocol_str:
                return 'SMTP'
            else:
                return 'OTHER'
        
        if 'protocol' in df.columns:
            df['protocol'] = df['protocol'].apply(normalize_protocol)
        else:
            # Inferir protocolo basado en puertos
            df['protocol'] = 'TCP'  # Default
            
            # Mapeo básico por puertos
            df.loc[df['dst_port'].isin([53]), 'protocol'] = 'DNS'
            df.loc[df['dst_port'].isin([80]), 'protocol'] = 'HTTP'
            df.loc[df['dst_port'].isin([443]), 'protocol'] = 'HTTPS'
            df.loc[df['dst_port'].isin([22]), 'protocol'] = 'SSH'
            df.loc[df['dst_port'].isin([21]), 'protocol'] = 'FTP'
            df.loc[df['dst_port'].isin([25, 587]), 'protocol'] = 'SMTP'
        
        return df
    
    def limpiar_metricas(self, df):
        """Limpia métricas numéricas"""
        logger.debug("Limpiando métricas numéricas...")
        
        def clean_numeric(val, default=0.0):
            if pd.isna(val) or val == '':
                return default
            try:
                return float(val)
            except:
                return default
        
        # Tamaño de paquete
        if 'packet_size' in df.columns:
            df['packet_size'] = df['packet_size'].apply(lambda x: clean_numeric(x, 0))
        else:
            # Intentar calcular desde otros campos
            size_cols = ['ip_length', 'tcp_length', 'udp_length']
            df['packet_size'] = 0
            for col in size_cols:
                if col in df.columns:
                    df['packet_size'] += df[col].apply(lambda x: clean_numeric(x, 0))
            
            # Si no hay datos, usar valor por defecto
            df['packet_size'] = df['packet_size'].apply(lambda x: max(x, 64))  # Mínimo 64 bytes
        
        # Duración
        if 'duration' in df.columns:
            df['duration'] = df['duration'].apply(lambda x: clean_numeric(x, 0))
        else:
            df['duration'] = 0.0
        
        # Validar rangos
        df['packet_size'] = df['packet_size'].clip(lower=0, upper=65535)
        df['duration'] = df['duration'].clip(lower=0, upper=3600)  # Max 1 hora
        
        return df
    
    def calcular_campos_derivados(self, df):
        """Calcula campos derivados necesarios para el modelo"""
        logger.debug("Calculando campos derivados...")
        
        # Calcular flow_bytes_per_sec
        df['flow_bytes_per_sec'] = 0.0
        mask = df['duration'] > 0
        df.loc[mask, 'flow_bytes_per_sec'] = df.loc[mask, 'packet_size'] / df.loc[mask, 'duration']
        
        # Calcular flow_packets_per_sec (asumiendo 1 paquete por registro)
        df['flow_packets_per_sec'] = 0.0
        df.loc[mask, 'flow_packets_per_sec'] = 1.0 / df.loc[mask, 'duration']
        
        # Campos adicionales con valores por defecto
        df['total_fwd_packets'] = 1
        df['total_backward_packets'] = 0
        df['total_length_fwd_packets'] = df['packet_size']
        df['total_length_backward_packets'] = 0
        
        # Estadísticas de paquetes (valores básicos)
        df['fwd_packet_length_max'] = df['packet_size']
        df['fwd_packet_length_min'] = df['packet_size']
        df['fwd_packet_length_mean'] = df['packet_size'].astype(float)
        df['fwd_packet_length_std'] = 0.0
        
        return df
    
    def validacion_final(self, df):
        """Validación final de datos"""
        logger.debug("Realizando validación final...")
        
        # Eliminar filas con valores críticos inválidos
        df = df[
            (df['src_ip'] != '0.0.0.0') | (df['dst_ip'] != '0.0.0.0')
        ]
        
        # Eliminar filas donde ambos puertos son 0
        df = df[
            (df['src_port'] != 0) | (df['dst_port'] != 0)
        ]
        
        # Validar que packet_size sea razonable
        df = df[
            (df['packet_size'] >= 20) & (df['packet_size'] <= 65535)
        ]
        
        return df
    
    def preparar_para_bd(self, df, archivo_origen):
        """Prepara DataFrame para inserción en base de datos"""
        logger.debug("Preparando datos para base de datos...")
        
        # Campos requeridos por el modelo TraficoRed
        campos_requeridos = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'packet_size', 'duration', 'flow_bytes_per_sec', 'flow_packets_per_sec',
            'total_fwd_packets', 'total_backward_packets',
            'total_length_fwd_packets', 'total_length_backward_packets',
            'fwd_packet_length_max', 'fwd_packet_length_min',
            'fwd_packet_length_mean', 'fwd_packet_length_std'
        ]
        
        # Asegurar que todos los campos existen
        for campo in campos_requeridos:
            if campo not in df.columns:
                if campo in ['tcp_flags']:
                    df[campo] = ''
                else:
                    df[campo] = 0
        
        # Añadir metadatos
        df['archivo_origen'] = os.path.basename(archivo_origen)
        df['procesado'] = False
        df['label'] = None
        df['confidence_score'] = None
        
        # Seleccionar solo las columnas necesarias
        columnas_finales = campos_requeridos + ['archivo_origen', 'procesado', 'label', 'confidence_score', 'tcp_flags']
        df_final = df[columnas_finales].copy()
        
        return df_final
    
    def guardar_en_bd(self, df, archivo_origen):
        """Guarda datos en base de datos Django"""
        if not DJANGO_AVAILABLE:
            logger.error("Django no disponible, no se puede guardar en BD")
            return 0
        
        logger.info(f"Guardando {len(df)} registros en base de datos...")
        
        registros_creados = 0
        errores = 0
        
        # Procesar en lotes
        for i in range(0, len(df), self.batch_size):
            batch = df.iloc[i:i+self.batch_size]
            batch_objects = []
            
            for _, row in batch.iterrows():
                try:
                    traffic_record = TraficoRed(
                        src_ip=str(row['src_ip']),
                        dst_ip=str(row['dst_ip']),
                        src_port=int(row['src_port']),
                        dst_port=int(row['dst_port']),
                        protocol=str(row['protocol'])[:10],
                        packet_size=int(row['packet_size']),
                        duration=float(row['duration']),
                        flow_bytes_per_sec=float(row['flow_bytes_per_sec']),
                        flow_packets_per_sec=float(row['flow_packets_per_sec']),
                        total_fwd_packets=int(row['total_fwd_packets']),
                        total_backward_packets=int(row['total_backward_packets']),
                        total_length_fwd_packets=int(row['total_length_fwd_packets']),
                        total_length_backward_packets=int(row['total_length_backward_packets']),
                        fwd_packet_length_max=int(row['fwd_packet_length_max']),
                        fwd_packet_length_min=int(row['fwd_packet_length_min']),
                        fwd_packet_length_mean=float(row['fwd_packet_length_mean']),
                        fwd_packet_length_std=float(row['fwd_packet_length_std']),
                        tcp_flags=str(row.get('tcp_flags', ''))[:50],
                        archivo_origen=str(row['archivo_origen']),
                        procesado=False
                    )
                    batch_objects.append(traffic_record)
                    
                except Exception as e:
                    logger.warning(f"Error creando objeto para fila {i}: {e}")
                    errores += 1
                    continue
            
            # Inserción en lote
            if batch_objects:
                try:
                    TraficoRed.objects.bulk_create(batch_objects, ignore_conflicts=True)
                    registros_creados += len(batch_objects)
                    logger.debug(f"Lote {i//self.batch_size + 1}: {len(batch_objects)} registros guardados")
                except Exception as e:
                    logger.error(f"Error en inserción de lote: {e}")
                    errores += len(batch_objects)
        
        logger.info(f"Guardado completado: {registros_creados} registros creados, {errores} errores")
        return registros_creados
    
    def procesar_archivo_csv(self, csv_file):
        """Procesa un archivo CSV completo"""
        try:
            archivo_path = os.path.join(self.csv_dir, csv_file)
            logger.info(f"Procesando archivo: {csv_file}")
            
            # Leer CSV
            df = self.leer_csv(archivo_path)
            
            if df.empty:
                logger.warning(f"Archivo CSV vacío: {csv_file}")
                return 0
            
            # Mapear columnas
            df = self.mapear_columnas(df)
            
            # Limpiar datos
            df = self.limpiar_datos(df)
            
            if df.empty:
                logger.warning(f"No hay datos válidos después de la limpieza: {csv_file}")
                return 0
            
            # Preparar para BD
            df = self.preparar_para_bd(df, csv_file)
            
            # Guardar en BD
            registros_creados = self.guardar_en_bd(df, csv_file)
            
            # Mover archivo a procesados
            if registros_creados > 0:
                self.mover_archivo_procesado(csv_file)
            else:
                self.mover_archivo_error(csv_file, "No se pudieron guardar datos")
            
            return registros_creados
            
        except Exception as e:
            logger.error(f"Error procesando {csv_file}: {e}")
            self.mover_archivo_error(csv_file, str(e))
            return 0
    
    def mover_archivo_procesado(self, csv_file):
        """Mueve archivo a directorio de procesados"""
        try:
            origen = os.path.join(self.csv_dir, csv_file)
            destino = os.path.join(self.processed_dir, csv_file)
            
            os.rename(origen, destino)
            logger.info(f"Archivo movido a procesados: {csv_file}")
            
        except Exception as e:
            logger.error(f"Error moviendo archivo a procesados: {e}")
    
    def mover_archivo_error(self, csv_file, error_msg):
        """Mueve archivo a directorio de errores"""
        try:
            origen = os.path.join(self.csv_dir, csv_file)
            destino = os.path.join(self.error_dir, csv_file)
            
            os.rename(origen, destino)
            logger.warning(f"Archivo movido a errores: {csv_file} - {error_msg}")
            
            # Crear archivo de log del error
            error_log = os.path.join(self.error_dir, f"{csv_file}.error.txt")
            with open(error_log, 'w') as f:
                f.write(f"Error: {error_msg}\n")
                f.write(f"Fecha: {datetime.now().isoformat()}\n")
            
        except Exception as e:
            logger.error(f"Error moviendo archivo a errores: {e}")
    
    def procesar_todos_csv(self):
        """Procesa todos los archivos CSV pendientes"""
        logger.info("Iniciando procesamiento de todos los archivos CSV")
        
        archivos = self.listar_archivos_csv()
        
        if not archivos:
            logger.info("No hay archivos CSV para procesar")
            return {"procesados": 0, "registros_totales": 0, "errores": 0}
        
        logger.info(f"Encontrados {len(archivos)} archivos CSV para procesar")
        
        total_procesados = 0
        total_registros = 0
        total_errores = 0
        
        for archivo in archivos:
            try:
                registros = self.procesar_archivo_csv(archivo)
                if registros > 0:
                    total_procesados += 1
                    total_registros += registros
                else:
                    total_errores += 1
                    
            except Exception as e:
                logger.error(f"Error procesando {archivo}: {e}")
                total_errores += 1
        
        resultado = {
            "procesados": total_procesados,
            "registros_totales": total_registros,
            "errores": total_errores
        }
        
        logger.info(f"Procesamiento completado: {resultado}")
        
        # Crear alerta si hay muchos errores
        if DJANGO_AVAILABLE and total_errores > 0 and total_errores >= total_procesados:
            create_system_alert(
                title='Muchos errores en procesamiento CSV',
                description=f'Se encontraron {total_errores} errores de {len(archivos)} archivos procesados',
                severity='medium',
                alert_type='processing_error',
                alert_data=resultado
            )
        
        return resultado
    
    def obtener_estadisticas(self):
        """Obtiene estadísticas del procesador"""
        try:
            pendientes = len(self.listar_archivos_csv())
            
            procesados = 0
            if os.path.exists(self.processed_dir):
                procesados = len([f for f in os.listdir(self.processed_dir) if f.endswith('.csv')])
            
            errores = 0
            if os.path.exists(self.error_dir):
                errores = len([f for f in os.listdir(self.error_dir) if f.endswith('.csv')])
            
            stats = {
                'archivos_pendientes': pendientes,
                'archivos_procesados': procesados,
                'archivos_con_error': errores,
                'directorio_csv': self.csv_dir,
                'directorio_procesados': self.processed_dir,
                'directorio_errores': self.error_dir
            }
            
            logger.info(f"Estadísticas: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {}


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='Procesador de archivos CSV de tráfico de red')
    parser.add_argument('--csv-dir', '-d', help='Directorio de archivos CSV')
    parser.add_argument('--file', '-f', help='Archivo CSV específico a procesar')
    parser.add_argument('--batch-size', '-b', type=int, default=1000, help='Tamaño de lote para BD')
    parser.add_argument('--stats', '-s', action='store_true', help='Mostrar estadísticas')
    parser.add_argument('--all', '-a', action='store_true', help='Procesar todos los archivos')
    
    args = parser.parse_args()
    
    # Crear procesador
    procesador = ProcesadorCSV(
        csv_dir=args.csv_dir,
        batch_size=args.batch_size
    )
    
    try:
        if args.stats:
            procesador.obtener_estadisticas()
            return
        
        if args.file:
            registros = procesador.procesar_archivo_csv(args.file)
            logger.info(f"Archivo {args.file} procesado: {registros} registros")
            return
        
        if args.all or not args.file:
            resultado = procesador.procesar_todos_csv()
            logger.info(f"Procesamiento masivo completado: {resultado}")
            return
            
    except Exception as e:
        logger.error(f"Error en procesamiento: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()