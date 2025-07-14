#!/usr/bin/env python3
"""
Sistema de captura automática de tráfico con Wireshark/tshark
Inicia captura después de 20 segundos del acceso inicial
"""

import subprocess
import time
import os
import sys
import threading
import signal
import logging
from datetime import datetime
from pathlib import Path

# Añadir el directorio raíz al path para importar Django
sys.path.append(str(Path(__file__).parent.parent))

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'anomalia_detection.settings.development')

try:
    import django
    django.setup()
    
    from apps.core.models import SystemConfiguration
    from apps.traffic.models import CaptureSession
    from apps.core.utils import create_system_alert
except ImportError as e:
    print(f"Error importando Django: {e}")
    print("Ejecutando en modo standalone")

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/traffic_capture.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CapturaTrafico:
    """Clase para manejar la captura de tráfico de red"""
    
    def __init__(self, interface="eth0", duration=300, capture_dir=None):
        self.interface = interface
        self.duration = duration
        self.capture_dir = capture_dir or "/media/captures/"
        self.process = None
        self.session_id = None
        self.capture_session = None
        self.running = False
        
        # Crear directorio si no existe
        os.makedirs(self.capture_dir, exist_ok=True)
        
        # Configurar manejo de señales
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Maneja señales de interrupción"""
        logger.info(f"Recibida señal {sig}, deteniendo captura...")
        self.detener_captura()
        sys.exit(0)
    
    def verificar_permisos(self):
        """Verifica permisos para captura de tráfico"""
        if os.geteuid() != 0:
            logger.error("Se requieren permisos de root para capturar tráfico")
            return False
        return True
    
    def verificar_tshark(self):
        """Verifica que tshark está instalado"""
        try:
            result = subprocess.run(['which', 'tshark'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"tshark encontrado en: {result.stdout.strip()}")
                return True
            else:
                logger.error("tshark no encontrado. Instalar con: sudo apt-get install tshark")
                return False
        except Exception as e:
            logger.error(f"Error verificando tshark: {e}")
            return False
    
    def verificar_interfaz(self):
        """Verifica que la interfaz de red existe"""
        try:
            result = subprocess.run(['ip', 'link', 'show', self.interface], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Interfaz {self.interface} encontrada")
                return True
            else:
                logger.error(f"Interfaz {self.interface} no encontrada")
                return False
        except Exception as e:
            logger.error(f"Error verificando interfaz: {e}")
            return False
    
    def obtener_configuracion_sistema(self):
        """Obtiene configuración del sistema Django"""
        try:
            config = SystemConfiguration.get_current_config()
            self.interface = config.network_interface
            self.duration = config.capture_duration
            logger.info(f"Configuración cargada: interfaz={self.interface}, duración={self.duration}s")
        except Exception as e:
            logger.warning(f"No se pudo cargar configuración del sistema: {e}")
            logger.info("Usando configuración por defecto")
    
    def crear_session_bd(self):
        """Crea sesión en base de datos"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.session_id = f"capture_{timestamp}"
            
            self.capture_session = CaptureSession.objects.create(
                session_id=self.session_id,
                interface=self.interface,
                duration=self.duration,
                status='PENDING'
            )
            logger.info(f"Sesión creada en BD: {self.session_id}")
        except Exception as e:
            logger.error(f"Error creando sesión en BD: {e}")
            # Continuar sin BD
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.session_id = f"capture_{timestamp}"
    
    def actualizar_estado_session(self, status, **kwargs):
        """Actualiza estado de la sesión en BD"""
        try:
            if self.capture_session:
                self.capture_session.status = status
                for key, value in kwargs.items():
                    if hasattr(self.capture_session, key):
                        setattr(self.capture_session, key, value)
                self.capture_session.save()
                logger.debug(f"Estado de sesión actualizado: {status}")
        except Exception as e:
            logger.error(f"Error actualizando estado de sesión: {e}")
    
    def generar_nombre_archivo(self):
        """Genera nombre único para archivo de captura"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"captura_{self.session_id}_{timestamp}.pcap"
        return os.path.join(self.capture_dir, filename)
    
    def iniciar_captura_automatica(self, delay=20):
        """Inicia captura después del delay especificado"""
        logger.info(f"Esperando {delay} segundos antes de iniciar captura...")
        time.sleep(delay)
        
        return self.capturar_trafico()
    
    def capturar_trafico(self):
        """Ejecuta tshark para capturar tráfico"""
        if not self.verificar_permisos():
            return False
        
        if not self.verificar_tshark():
            return False
        
        if not self.verificar_interfaz():
            return False
        
        # Obtener configuración del sistema
        self.obtener_configuracion_sistema()
        
        # Crear sesión en BD
        self.crear_session_bd()
        
        # Generar archivo de salida
        filepath = self.generar_nombre_archivo()
        
        # Comando tshark
        cmd = [
            "tshark", 
            "-i", self.interface,
            "-a", f"duration:{self.duration}",
            "-w", filepath,
            "-q",  # Modo silencioso
            "-f", "not host 127.0.0.1"  # Excluir localhost
        ]
        
        logger.info(f"Iniciando captura con comando: {' '.join(cmd)}")
        logger.info(f"Archivo de salida: {filepath}")
        
        try:
            # Actualizar estado a running
            self.actualizar_estado_session('RUNNING', 
                                         started_at=datetime.now(),
                                         pcap_file_path=filepath)
            
            # Ejecutar captura
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.running = True
            logger.info(f"Captura iniciada (PID: {self.process.pid})")
            
            # Esperar a que termine
            stdout, stderr = self.process.communicate(timeout=self.duration + 60)
            
            self.running = False
            
            if self.process.returncode == 0:
                # Captura exitosa
                if os.path.exists(filepath):
                    file_size = os.path.getsize(filepath)
                    
                    # Estimar número de paquetes
                    estimated_packets = self.estimar_paquetes(filepath)
                    
                    logger.info(f"Captura completada exitosamente")
                    logger.info(f"Archivo: {filepath}")
                    logger.info(f"Tamaño: {file_size:,} bytes")
                    logger.info(f"Paquetes estimados: {estimated_packets:,}")
                    
                    # Actualizar estado en BD
                    self.actualizar_estado_session('COMPLETED',
                                                 completed_at=datetime.now(),
                                                 packets_captured=estimated_packets,
                                                 bytes_captured=file_size)
                    
                    # Iniciar procesamiento automático
                    self.iniciar_procesamiento_automatico(filepath)
                    
                    return filepath
                else:
                    raise Exception("Archivo PCAP no fue creado")
            else:
                error_msg = stderr or "Error desconocido en tshark"
                raise Exception(f"Error en tshark (código {self.process.returncode}): {error_msg}")
                
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout en captura después de {self.duration + 60} segundos"
            logger.error(error_msg)
            self.detener_captura()
            self.actualizar_estado_session('FAILED', 
                                         completed_at=datetime.now(),
                                         error_message=error_msg)
            return False
            
        except Exception as e:
            error_msg = f"Error en captura: {str(e)}"
            logger.error(error_msg)
            self.detener_captura()
            self.actualizar_estado_session('FAILED',
                                         completed_at=datetime.now(),
                                         error_message=error_msg)
            
            # Crear alerta de error
            try:
                create_system_alert(
                    title='Error en captura de tráfico',
                    description=error_msg,
                    severity='high',
                    alert_type='capture_error'
                )
            except:
                pass
            
            return False
    
    def detener_captura(self):
        """Detiene la captura en curso"""
        if self.process and self.running:
            try:
                logger.info("Deteniendo captura...")
                self.process.terminate()
                
                # Esperar a que termine gracefully
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("Proceso no terminó gracefully, forzando...")
                    self.process.kill()
                    self.process.wait()
                
                self.running = False
                logger.info("Captura detenida")
                
                # Actualizar estado
                self.actualizar_estado_session('CANCELLED',
                                             completed_at=datetime.now())
                
            except Exception as e:
                logger.error(f"Error deteniendo captura: {e}")
    
    def estimar_paquetes(self, filepath):
        """Estima el número de paquetes usando capinfos"""
        try:
            result = subprocess.run(['capinfos', '-c', filepath], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Number of packets' in line:
                        return int(line.split(':')[1].strip())
            
            # Fallback: estimar por tamaño de archivo
            file_size = os.path.getsize(filepath)
            return file_size // 100  # Estimación muy básica
            
        except Exception as e:
            logger.warning(f"Error estimando paquetes: {e}")
            file_size = os.path.getsize(filepath)
            return file_size // 100
    
    def iniciar_procesamiento_automatico(self, pcap_filepath):
        """Inicia procesamiento automático del PCAP"""
        try:
            # Verificar configuración automática
            config = SystemConfiguration.get_current_config()
            if not config.auto_process_csv:
                logger.info("Procesamiento automático deshabilitado")
                return
            
            logger.info("Iniciando procesamiento automático...")
            
            # Ejecutar script de conversión
            flow_script = os.path.join(os.path.dirname(__file__), 'flow.js')
            if os.path.exists(flow_script):
                subprocess.Popen(['node', flow_script, pcap_filepath])
                logger.info("Script de conversión iniciado")
            else:
                logger.warning("Script flow.js no encontrado")
                
        except Exception as e:
            logger.error(f"Error iniciando procesamiento automático: {e}")
    
    def limpiar_archivos_antiguos(self, dias=7):
        """Limpia archivos PCAP antiguos"""
        try:
            import time
            cutoff_time = time.time() - (dias * 24 * 3600)
            
            archivos_eliminados = 0
            for filename in os.listdir(self.capture_dir):
                if filename.endswith('.pcap'):
                    filepath = os.path.join(self.capture_dir, filename)
                    if os.path.getmtime(filepath) < cutoff_time:
                        os.remove(filepath)
                        archivos_eliminados += 1
                        logger.info(f"Archivo antiguo eliminado: {filename}")
            
            logger.info(f"Limpieza completada: {archivos_eliminados} archivos eliminados")
            
        except Exception as e:
            logger.error(f"Error en limpieza de archivos: {e}")
    
    def obtener_estadisticas(self):
        """Obtiene estadísticas de capturas"""
        try:
            archivos_pcap = [f for f in os.listdir(self.capture_dir) if f.endswith('.pcap')]
            
            total_archivos = len(archivos_pcap)
            total_tamaño = sum(
                os.path.getsize(os.path.join(self.capture_dir, f)) 
                for f in archivos_pcap
            )
            
            logger.info(f"Estadísticas de captura:")
            logger.info(f"- Total archivos PCAP: {total_archivos}")
            logger.info(f"- Tamaño total: {total_tamaño:,} bytes")
            
            return {
                'total_archivos': total_archivos,
                'total_tamaño': total_tamaño,
                'directorio': self.capture_dir
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {}


def main():
    """Función principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Sistema de captura de tráfico de red')
    parser.add_argument('--interface', '-i', default='eth0', 
                       help='Interfaz de red (default: eth0)')
    parser.add_argument('--duration', '-d', type=int, default=300,
                       help='Duración en segundos (default: 300)')
    parser.add_argument('--delay', type=int, default=20,
                       help='Delay antes de iniciar (default: 20)')
    parser.add_argument('--output-dir', '-o', 
                       help='Directorio de salida (default: /media/captures/)')
    parser.add_argument('--no-delay', action='store_true',
                       help='Iniciar inmediatamente sin delay')
    parser.add_argument('--cleanup', action='store_true',
                       help='Limpiar archivos antiguos y salir')
    parser.add_argument('--stats', action='store_true',
                       help='Mostrar estadísticas y salir')
    
    args = parser.parse_args()
    
    # Crear instancia de captura
    captura = CapturaTrafico(
        interface=args.interface,
        duration=args.duration,
        capture_dir=args.output_dir
    )
    
    # Ejecutar acción solicitada
    if args.cleanup:
        captura.limpiar_archivos_antiguos()
        return
    
    if args.stats:
        captura.obtener_estadisticas()
        return
    
    # Iniciar captura
    if args.no_delay:
        resultado = captura.capturar_trafico()
    else:
        resultado = captura.iniciar_captura_automatica(args.delay)
    
    if resultado:
        logger.info(f"Captura completada exitosamente: {resultado}")
        sys.exit(0)
    else:
        logger.error("La captura falló")
        sys.exit(1)


if __name__ == "__main__":
    main()