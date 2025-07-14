#!/usr/bin/env node
/**
 * Script Node.js para convertir archivos .pcap a CSV usando Flowmeter.
 * Ejecuta Flowmeter para extraer características de flujo de red.
 */

const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

class FlowmeterProcessor {
    constructor() {
        this.inputDir = '/tmp/captures';
        this.outputDir = '/tmp/csv_output';
        this.flowmeterPath = 'flowmeter'; // Asume que está en PATH
        
        // Crear directorio de salida si no existe
        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
    }
    
    /**
     * Verifica si Flowmeter está disponible en el sistema.
     */
    async checkFlowmeter() {
        try {
            await execAsync('flowmeter --version');
            console.log('Flowmeter disponible en el sistema');
            return true;
        } catch (error) {
            console.log('Flowmeter no disponible, simulando procesamiento...');
            return false;
        }
    }
    
    /**
     * Procesa un archivo PCAP y genera CSV con características de flujo.
     */
    async processPcapFile(pcapFilePath) {
        const fileName = path.basename(pcapFilePath, '.pcap');
        const csvOutputPath = path.join(this.outputDir, `${fileName}_flows.csv`);
        
        console.log(`Procesando: ${pcapFilePath}`);
        console.log(`Salida CSV: ${csvOutputPath}`);
        
        const flowmeterAvailable = await this.checkFlowmeter();
        
        if (flowmeterAvailable) {
            return await this.runRealFlowmeter(pcapFilePath, csvOutputPath);
        } else {
            return await this.simulateFlowmeter(pcapFilePath, csvOutputPath);
        }
    }
    
    /**
     * Ejecuta Flowmeter real.
     */
    async runRealFlowmeter(pcapPath, csvPath) {
        try {
            const command = `flowmeter -f ${pcapPath} -o ${csvPath}`;
            console.log(`Ejecutando: ${command}`);
            
            const { stdout, stderr } = await execAsync(command);
            
            if (stderr) {
                console.error('Advertencias de Flowmeter:', stderr);
            }
            
            console.log('Flowmeter completado:', stdout);
            
            // Verificar que el archivo CSV fue creado
            if (fs.existsSync(csvPath)) {
                const stats = fs.statSync(csvPath);
                console.log(`Archivo CSV generado: ${csvPath} (${stats.size} bytes)`);
                return csvPath;
            } else {
                throw new Error('No se generó el archivo CSV');
            }
            
        } catch (error) {
            console.error('Error ejecutando Flowmeter:', error.message);
            throw error;
        }
    }
    
    /**
     * Simula el procesamiento de Flowmeter para desarrollo.
     */
    async simulateFlowmeter(pcapPath, csvPath) {
        console.log('Simulando procesamiento de Flowmeter...');
        
        // Generar datos CSV simulados con características típicas de flujo
        const csvHeader = [
            'Flow ID',
            'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
            'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
            'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
            'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
            'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
            'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
            'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Bwd IAT Max', 'Bwd IAT Min', 'Label'
        ].join(',');
        
        const sampleRows = [];
        
        // Generar 50 filas de datos simulados
        for (let i = 1; i <= 50; i++) {
            const srcIp = `192.168.1.${Math.floor(Math.random() * 254) + 1}`;
            const dstIp = `10.0.0.${Math.floor(Math.random() * 254) + 1}`;
            const srcPort = Math.floor(Math.random() * 65535) + 1;
            const dstPort = [80, 443, 22, 21, 25][Math.floor(Math.random() * 5)];
            const protocol = Math.random() > 0.8 ? 'UDP' : 'TCP';
            
            const flowDuration = (Math.random() * 100).toFixed(6);
            const totFwdPkts = Math.floor(Math.random() * 100) + 1;
            const totBwdPkts = Math.floor(Math.random() * 100) + 1;
            
            const row = [
                `flow_${i}`,
                srcIp, srcPort, dstIp, dstPort, protocol,
                Date.now() + i * 1000,
                flowDuration,
                totFwdPkts, totBwdPkts,
                Math.floor(Math.random() * 10000),
                Math.floor(Math.random() * 10000),
                Math.floor(Math.random() * 1500),
                40,
                (Math.random() * 800).toFixed(2),
                (Math.random() * 200).toFixed(2),
                Math.floor(Math.random() * 1500),
                40,
                (Math.random() * 800).toFixed(2),
                (Math.random() * 200).toFixed(2),
                (Math.random() * 100000).toFixed(2),
                (Math.random() * 1000).toFixed(2),
                (Math.random() * 0.1).toFixed(6),
                (Math.random() * 0.05).toFixed(6),
                (Math.random() * 1).toFixed(6),
                0.000001,
                (Math.random() * 1).toFixed(6),
                (Math.random() * 0.1).toFixed(6),
                (Math.random() * 0.05).toFixed(6),
                (Math.random() * 1).toFixed(6),
                0.000001,
                (Math.random() * 1).toFixed(6),
                (Math.random() * 0.1).toFixed(6),
                (Math.random() * 0.05).toFixed(6),
                (Math.random() * 1).toFixed(6),
                0.000001,
                'BENIGN' // Label por defecto
            ].join(',');
            
            sampleRows.push(row);
        }
        
        const csvContent = [csvHeader, ...sampleRows].join('\n');
        
        // Escribir archivo CSV
        fs.writeFileSync(csvPath, csvContent);
        
        console.log(`Archivo CSV simulado generado: ${csvPath}`);
        return csvPath;
    }
    
    /**
     * Procesa todos los archivos PCAP en el directorio de entrada.
     */
    async processAllPcapFiles() {
        const files = fs.readdirSync(this.inputDir)
            .filter(file => file.endsWith('.pcap'));
        
        if (files.length === 0) {
            console.log('No se encontraron archivos PCAP para procesar');
            return [];
        }
        
        const results = [];
        
        for (const file of files) {
            try {
                const pcapPath = path.join(this.inputDir, file);
                const csvPath = await this.processPcapFile(pcapPath);
                results.push(csvPath);
            } catch (error) {
                console.error(`Error procesando ${file}:`, error.message);
            }
        }
        
        return results;
    }
    
    /**
     * Limpia archivos antiguos.
     */
    cleanupOldFiles(maxAgeHours = 24) {
        const maxAge = maxAgeHours * 60 * 60 * 1000; // Convertir a millisegundos
        const now = Date.now();
        
        [this.inputDir, this.outputDir].forEach(dir => {
            if (fs.existsSync(dir)) {
                const files = fs.readdirSync(dir);
                files.forEach(file => {
                    const filePath = path.join(dir, file);
                    const stats = fs.statSync(filePath);
                    
                    if (now - stats.mtime.getTime() > maxAge) {
                        fs.unlinkSync(filePath);
                        console.log(`Archivo eliminado: ${filePath}`);
                    }
                });
            }
        });
    }
}

// Función principal
async function main() {
    console.log('=== Iniciando procesamiento con Flowmeter ===');
    
    const processor = new FlowmeterProcessor();
    
    try {
        // Procesar archivos PCAP
        const csvFiles = await processor.processAllPcapFiles();
        
        if (csvFiles.length > 0) {
            console.log('\nArchivos CSV generados:');
            csvFiles.forEach(file => console.log(`  - ${file}`));
        }
        
        // Limpiar archivos antiguos
        processor.cleanupOldFiles(24);
        
        console.log('\n=== Procesamiento completado ===');
        
    } catch (error) {
        console.error('Error en procesamiento:', error.message);
        process.exit(1);
    }
}

// Ejecutar si es llamado directamente
if (require.main === module) {
    main();
}

module.exports = FlowmeterProcessor;