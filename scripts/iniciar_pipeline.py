#!/usr/bin/env python3
"""
Pipeline automatizado completo para el sistema de detección de anomalías.
Ejecuta la secuencia completa: captura -> conversión -> procesamiento -> predicción
"""

import os
import sys
import time
import threading
import logging
import subprocess
import argparse
from datetime import datetime

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/anomalia_pipeline.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PipelineAutomatizado:
    """Pipeline completo para procesamiento de tráfico de red"""
    
    def __init__(self, config=None):
        self.config = config or {
            'interface': 'eth0',
            'capture_duration': 300,
            'capture_delay': 20,
            'auto_cleanup': True,
            'max_file_age_days': 7
        }
        self.is_running = False
        self.capture_thread = None
        
    def verificar_dependencias(self):
        """Verify all required dependencies are available"""
        dependencies = {
            'tshark': ['tshark', '--version'],
            'node': ['node', '--version'],
            'python': ['python3', '--version']
        }
        
        missing = []
        for name, cmd in dependencies.items():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    missing.append(name)
                else:
                    logger.info(f"{name} is available")
            except FileNotFoundError:
                missing.append(name)
        
        if missing:
            logger.error(f"Missing dependencies: {', '.join(missing)}")
            return False
        
        return True
    
    def ejecutar_captura(self):
        """Execute traffic capture step"""
        logger.info("Step 1: Starting traffic capture...")
        
        cmd = [
            'python3', 'scripts/captura_wireshark.py',
            '--interface', self.config['interface'],
            '--duration', str(self.config['capture_duration']),
            '--delay', str(self.config['capture_delay'])
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("Traffic capture completed successfully")
                return True
            else:
                logger.error(f"Capture failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error in capture step: {e}")
            return False
    
    def ejecutar_conversion(self):
        """Execute PCAP to CSV conversion step"""
        logger.info("Step 2: Converting PCAP to CSV...")
        
        cmd = ['node', 'scripts/flow.js', '--all']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd='.')
            if result.returncode == 0:
                logger.info("PCAP to CSV conversion completed")
                return True
            else:
                logger.warning("Conversion had issues, generating synthetic data...")
                # Generate synthetic data as fallback
                cmd_synthetic = ['node', 'scripts/flow.js', '--synthetic']
                result = subprocess.run(cmd_synthetic, capture_output=True, text=True, cwd='.')
                return result.returncode == 0
        except Exception as e:
            logger.error(f"Error in conversion step: {e}")
            return False
    
    def ejecutar_procesamiento(self):
        """Execute CSV processing and database insertion"""
        logger.info("Step 3: Processing CSV data...")
        
        cmd = ['python3', 'scripts/procesar_csv.py', '--all']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("CSV processing completed")
                return True
            else:
                logger.error(f"Processing failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error in processing step: {e}")
            return False
    
    def ejecutar_prediccion(self):
        """Execute ML prediction step"""
        logger.info("Step 4: Running ML predictions...")
        
        cmd = ['python3', 'scripts/predecir_csv.py', '--predict']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("ML predictions completed")
                return True
            else:
                logger.error(f"Prediction failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error in prediction step: {e}")
            return False
    
    def limpiar_archivos(self):
        """Clean old files if auto cleanup is enabled"""
        if not self.config.get('auto_cleanup', True):
            return
        
        logger.info("Step 5: Cleaning old files...")
        
        try:
            # Clean old capture files
            cmd_clean = [
                'python3', 'scripts/captura_wireshark.py', 
                '--clean'
            ]
            subprocess.run(cmd_clean, capture_output=True)
            
            logger.info("File cleanup completed")
            
        except Exception as e:
            logger.warning(f"Error in cleanup step: {e}")
    
    def ejecutar_pipeline_completo(self):
        """Execute the complete pipeline"""
        logger.info("="*50)
        logger.info("STARTING COMPLETE ANOMALY DETECTION PIPELINE")
        logger.info("="*50)
        
        start_time = datetime.now()
        
        # Verify dependencies first
        if not self.verificar_dependencias():
            logger.error("Pipeline aborted due to missing dependencies")
            return False
        
        steps = [
            ("Traffic Capture", self.ejecutar_captura),
            ("PCAP Conversion", self.ejecutar_conversion),
            ("Data Processing", self.ejecutar_procesamiento),
            ("ML Prediction", self.ejecutar_prediccion),
            ("Cleanup", self.limpiar_archivos)
        ]
        
        successful_steps = 0
        
        for step_name, step_func in steps:
            try:
                logger.info(f"Executing: {step_name}")
                success = step_func()
                
                if success:
                    successful_steps += 1
                    logger.info(f"✓ {step_name} completed successfully")
                else:
                    logger.error(f"✗ {step_name} failed")
                    
                # Small delay between steps
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"✗ {step_name} failed with exception: {e}")
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        logger.info("="*50)
        logger.info("PIPELINE EXECUTION SUMMARY")
        logger.info("="*50)
        logger.info(f"Total steps: {len(steps)}")
        logger.info(f"Successful steps: {successful_steps}")
        logger.info(f"Failed steps: {len(steps) - successful_steps}")
        logger.info(f"Execution time: {duration}")
        logger.info(f"Success rate: {(successful_steps/len(steps)*100):.1f}%")
        
        success = successful_steps >= len(steps) - 1  # Allow cleanup to fail
        
        if success:
            logger.info("🎉 Pipeline completed successfully!")
        else:
            logger.warning("⚠️  Pipeline completed with errors")
        
        return success
    
    def ejecutar_pipeline_continuo(self, interval_minutes=30):
        """Execute pipeline continuously at specified intervals"""
        logger.info(f"Starting continuous pipeline (every {interval_minutes} minutes)")
        
        self.is_running = True
        
        while self.is_running:
            try:
                self.ejecutar_pipeline_completo()
                
                if self.is_running:  # Check if we should continue
                    logger.info(f"Waiting {interval_minutes} minutes for next execution...")
                    time.sleep(interval_minutes * 60)
                    
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, stopping pipeline...")
                self.is_running = False
            except Exception as e:
                logger.error(f"Unexpected error in continuous pipeline: {e}")
                time.sleep(60)  # Wait a minute before retrying
    
    def detener_pipeline(self):
        """Stop the continuous pipeline"""
        self.is_running = False
        logger.info("Pipeline stop requested")


def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(description="Automated anomaly detection pipeline")
    parser.add_argument('--mode', choices=['once', 'continuous'], default='once',
                      help='Run pipeline once or continuously')
    parser.add_argument('--interval', type=int, default=30,
                      help='Interval in minutes for continuous mode (default: 30)')
    parser.add_argument('--interface', default='eth0',
                      help='Network interface for capture (default: eth0)')
    parser.add_argument('--duration', type=int, default=300,
                      help='Capture duration in seconds (default: 300)')
    parser.add_argument('--no-cleanup', action='store_true',
                      help='Disable automatic file cleanup')
    
    args = parser.parse_args()
    
    # Create pipeline configuration
    config = {
        'interface': args.interface,
        'capture_duration': args.duration,
        'capture_delay': 20,
        'auto_cleanup': not args.no_cleanup,
        'max_file_age_days': 7
    }
    
    # Create pipeline instance
    pipeline = PipelineAutomatizado(config)
    
    try:
        if args.mode == 'once':
            success = pipeline.ejecutar_pipeline_completo()
            sys.exit(0 if success else 1)
        else:
            pipeline.ejecutar_pipeline_continuo(args.interval)
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user")
        pipeline.detener_pipeline()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()