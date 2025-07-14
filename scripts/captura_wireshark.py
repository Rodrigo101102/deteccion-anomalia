#!/usr/bin/env python3
"""
Script para captura de tráfico de red usando Wireshark/tshark.
Automatiza la captura después de 20 segundos del inicio del sistema.
"""

import subprocess
import os
import time
import logging
from datetime import datetime
import signal
import sys

# Configuración del logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/capture.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class WiresharkCapture:
    """Clase para manejar la captura de tráfico con Wireshark."""
    
    def __init__(self, interface='eth0', capture_dir='/tmp/captures'):
        """
        Inicializa la captura de Wireshark.
        
        Args:
            interface: Interfaz de red para capturar
            capture_dir: Directorio donde guardar los archivos .pcap
        """
        self.interface = interface
        self.capture_dir = capture_dir
        self.process = None
        self.session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pcap_file = os.path.join(capture_dir, f'traffic_{self.session_id}.pcap')
        
        # Crear directorio si no existe
        os.makedirs(capture_dir, exist_ok=True)
        
        # Registrar manejador de señales para limpieza
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Manejador de señales para limpieza ordenada."""
        logger.info(f"Recibida señal {signum}, deteniendo captura...")
        self.stop_capture()
        sys.exit(0)
    
    def start_capture(self, duration=300, filter_expr=''):
        """
        Inicia la captura de tráfico.
        
        Args:
            duration: Duración de la captura en segundos (por defecto 5 minutos)
            filter_expr: Filtro de captura de Wireshark (opcional)
        """
        try:
            logger.info(f"Iniciando captura en interfaz {self.interface}")
            logger.info(f"Archivo de salida: {self.pcap_file}")
            
            # Comando para tshark (versión CLI de Wireshark)
            cmd = [
                'tshark',
                '-i', self.interface,
                '-w', self.pcap_file,
                '-a', f'duration:{duration}'
            ]
            
            # Agregar filtro si se especifica
            if filter_expr:
                cmd.extend(['-f', filter_expr])
                logger.info(f"Aplicando filtro: {filter_expr}")
            
            # Iniciar proceso de captura
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            logger.info(f"Captura iniciada con PID: {self.process.pid}")
            
            # Esperar a que termine la captura
            stdout, stderr = self.process.communicate()
            
            if self.process.returncode == 0:
                logger.info("Captura completada exitosamente")
                return self.pcap_file
            else:
                logger.error(f"Error en captura: {stderr.decode()}")
                return None
                
        except FileNotFoundError:
            logger.error("tshark no está instalado. Instale Wireshark primero.")
            return None
        except Exception as e:
            logger.error(f"Error inesperado: {e}")
            return None
    
    def stop_capture(self):
        """Detiene la captura activa."""
        if self.process and self.process.poll() is None:
            logger.info("Deteniendo captura...")
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("Proceso no terminó, forzando...")
                self.process.kill()
    
    def get_file_info(self):
        """Obtiene información del archivo capturado."""
        if os.path.exists(self.pcap_file):
            size = os.path.getsize(self.pcap_file)
            return {
                'file': self.pcap_file,
                'size': size,
                'size_mb': round(size / (1024 * 1024), 2)
            }
        return None

def auto_capture_after_delay(delay_seconds=20):
    """
    Inicia captura automática después del delay especificado.
    
    Args:
        delay_seconds: Segundos a esperar antes de iniciar captura
    """
    logger.info(f"Esperando {delay_seconds} segundos antes de iniciar captura...")
    time.sleep(delay_seconds)
    
    # Inicializar captura
    capture = WiresharkCapture()
    
    # Iniciar captura con filtro básico para tráfico web
    filter_expr = 'tcp port 80 or tcp port 443 or tcp port 22'
    pcap_file = capture.start_capture(duration=300, filter_expr=filter_expr)
    
    if pcap_file:
        info = capture.get_file_info()
        logger.info(f"Archivo generado: {info['file']} ({info['size_mb']} MB)")
        return pcap_file
    else:
        logger.error("No se pudo completar la captura")
        return None

def main():
    """Función principal del script."""
    logger.info("=== Iniciando sistema de captura de tráfico ===")
    
    # Verificar si tshark está disponible
    try:
        subprocess.run(['tshark', '--version'], 
                      capture_output=True, check=True)
        logger.info("tshark disponible")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("tshark no está disponible. Simulando captura...")
        
        # Crear archivo simulado para desarrollo
        capture_dir = '/tmp/captures'
        os.makedirs(capture_dir, exist_ok=True)
        session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        dummy_file = os.path.join(capture_dir, f'traffic_{session_id}.pcap')
        
        time.sleep(20)  # Simular delay
        
        with open(dummy_file, 'w') as f:
            f.write("# Archivo PCAP simulado para desarrollo\n")
            f.write("# En producción, aquí habría datos de captura reales\n")
        
        logger.info(f"Archivo simulado creado: {dummy_file}")
        return dummy_file
    
    # Ejecutar captura automática
    return auto_capture_after_delay(20)

if __name__ == "__main__":
    main()