#!/usr/bin/env node
/**
 * Script Node.js para convertir archivos PCAP a CSV usando herramientas de análisis de flujo
 * Procesa archivos .pcap y genera CSV para análisis de machine learning
 */

const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const execAsync = promisify(exec);

class FlowProcessor {
    constructor() {
        this.inputDir = '/media/captures/';
        this.outputDir = '/media/csv_files/';
        this.processedDir = path.join(this.outputDir, 'processed');
        this.logFile = '/var/log/flow_processor.log';
        
        // Crear directorios si no existen
        this.ensureDirectories();
    }

    ensureDirectories() {
        const dirs = [this.inputDir, this.outputDir, this.processedDir];
        dirs.forEach(dir => {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
                this.log(`Directorio creado: ${dir}`);
            }
        });
    }

    log(message) {
        const timestamp = new Date().toISOString();
        const logMessage = `${timestamp} - ${message}\n`;
        
        console.log(message);
        
        try {
            fs.appendFileSync(this.logFile, logMessage);
        } catch (error) {
            console.error('Error escribiendo log:', error.message);
        }
    }

    async checkDependencies() {
        const tools = [
            { name: 'tshark', command: 'tshark --version' },
            { name: 'capinfos', command: 'capinfos --version' }
        ];

        for (const tool of tools) {
            try {
                await execAsync(tool.command);
                this.log(`✓ ${tool.name} está disponible`);
            } catch (error) {
                this.log(`✗ ${tool.name} no está disponible: ${error.message}`);
                throw new Error(`Dependencia faltante: ${tool.name}`);
            }
        }
    }

    async getPacketInfo(pcapFile) {
        try {
            const { stdout } = await execAsync(`capinfos -c -s -d "${pcapFile}"`);
            
            const info = {
                packets: 0,
                size: 0,
                duration: 0
            };

            const lines = stdout.split('\n');
            for (const line of lines) {
                if (line.includes('Number of packets')) {
                    info.packets = parseInt(line.split(':')[1].trim());
                } else if (line.includes('File size')) {
                    const sizeMatch = line.match(/(\d+)/);
                    if (sizeMatch) info.size = parseInt(sizeMatch[1]);
                } else if (line.includes('Capture duration')) {
                    const durationMatch = line.match(/([\d.]+) seconds/);
                    if (durationMatch) info.duration = parseFloat(durationMatch[1]);
                }
            }

            return info;
        } catch (error) {
            this.log(`Error obteniendo información del PCAP: ${error.message}`);
            return { packets: 0, size: 0, duration: 0 };
        }
    }

    async processPcapToCSV(pcapFile, outputFile = null) {
        try {
            this.log(`Iniciando procesamiento de ${pcapFile}`);

            // Verificar que el archivo existe
            if (!fs.existsSync(pcapFile)) {
                throw new Error(`Archivo PCAP no encontrado: ${pcapFile}`);
            }

            // Generar nombre de archivo de salida si no se proporciona
            if (!outputFile) {
                const baseName = path.basename(pcapFile, '.pcap');
                outputFile = path.join(this.outputDir, `${baseName}.csv`);
            }

            // Obtener información del PCAP
            const packetInfo = await this.getPacketInfo(pcapFile);
            this.log(`PCAP info - Paquetes: ${packetInfo.packets}, Tamaño: ${packetInfo.size} bytes, Duración: ${packetInfo.duration}s`);

            // Comando tshark para extraer campos relevantes
            const fields = [
                'ip.src',           // IP origen
                'ip.dst',           // IP destino  
                'tcp.srcport',      // Puerto TCP origen
                'tcp.dstport',      // Puerto TCP destino
                'udp.srcport',      // Puerto UDP origen
                'udp.dstport',      // Puerto UDP destino
                'frame.protocols',  // Protocolos
                'frame.len',        // Longitud del frame
                'frame.time_relative', // Tiempo relativo
                'tcp.flags',        // Flags TCP
                'ip.proto',         // Protocolo IP
                'frame.number',     // Número de frame
                'ip.len',           // Longitud IP
                'tcp.len',          // Longitud TCP
                'udp.length'        // Longitud UDP
            ];

            const tsharkCommand = [
                'tshark',
                '-r', pcapFile,
                '-T', 'fields',
                '-e', fields.join(' -e '),
                '-E', 'header=y',
                '-E', 'separator=,',
                '-E', 'quote=d',
                '-E', 'occurrence=f'
            ].join(' ');

            this.log(`Ejecutando: ${tsharkCommand}`);

            // Ejecutar tshark y procesar salida
            const { stdout, stderr } = await execAsync(`${tsharkCommand} > "${outputFile}"`);

            if (stderr && stderr.trim()) {
                this.log(`Advertencias de tshark: ${stderr}`);
            }

            // Verificar que se generó el archivo
            if (!fs.existsSync(outputFile)) {
                throw new Error('Archivo CSV no fue generado');
            }

            // Procesar y limpiar el CSV
            await this.cleanAndNormalizeCSV(outputFile);

            const outputSize = fs.statSync(outputFile).size;
            this.log(`CSV generado exitosamente: ${outputFile} (${outputSize} bytes)`);

            return {
                success: true,
                inputFile: pcapFile,
                outputFile: outputFile,
                inputSize: packetInfo.size,
                outputSize: outputSize,
                packets: packetInfo.packets
            };

        } catch (error) {
            this.log(`Error procesando PCAP: ${error.message}`);
            throw error;
        }
    }

    async cleanAndNormalizeCSV(csvFile) {
        try {
            this.log(`Limpiando y normalizando CSV: ${csvFile}`);

            // Leer archivo CSV
            const csvContent = fs.readFileSync(csvFile, 'utf8');
            const lines = csvContent.split('\n');

            if (lines.length < 2) {
                throw new Error('CSV vacío o sin datos');
            }

            // Procesar header
            const header = lines[0].split(',').map(field => field.replace(/"/g, '').trim());
            
            // Mapear campos a nombres estándar
            const fieldMapping = {
                'ip.src': 'src_ip',
                'ip.dst': 'dst_ip',
                'tcp.srcport': 'src_port',
                'tcp.dstport': 'dst_port',
                'udp.srcport': 'src_port_udp',
                'udp.dstport': 'dst_port_udp',
                'frame.len': 'packet_size',
                'frame.time_relative': 'relative_time',
                'tcp.flags': 'tcp_flags',
                'ip.proto': 'protocol_num',
                'frame.protocols': 'protocols',
                'ip.len': 'ip_length',
                'tcp.len': 'tcp_length',
                'udp.length': 'udp_length'
            };

            // Crear nuevo header normalizado
            const normalizedHeader = header.map(field => fieldMapping[field] || field);
            
            // Procesar datos
            const processedLines = [normalizedHeader.join(',')];
            let validRows = 0;
            let skippedRows = 0;

            for (let i = 1; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;

                const fields = this.parseCSVLine(line);
                if (fields.length !== header.length) {
                    skippedRows++;
                    continue;
                }

                // Procesar y validar campos
                const processedFields = this.processFields(fields, header);
                
                if (this.isValidRow(processedFields)) {
                    processedLines.push(processedFields.join(','));
                    validRows++;
                } else {
                    skippedRows++;
                }
            }

            // Escribir archivo limpio
            fs.writeFileSync(csvFile, processedLines.join('\n'));
            
            this.log(`CSV procesado: ${validRows} filas válidas, ${skippedRows} filas omitidas`);

        } catch (error) {
            this.log(`Error limpiando CSV: ${error.message}`);
            throw error;
        }
    }

    parseCSVLine(line) {
        const fields = [];
        let current = '';
        let inQuotes = false;

        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                fields.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        
        fields.push(current.trim());
        return fields;
    }

    processFields(fields, header) {
        return fields.map((field, index) => {
            const headerName = header[index];
            let value = field.replace(/"/g, '').trim();

            // Procesar campos específicos
            switch (headerName) {
                case 'tcp.srcport':
                case 'tcp.dstport':
                case 'udp.srcport':
                case 'udp.dstport':
                    // Combinar puertos TCP y UDP
                    const tcpPort = fields[header.indexOf('tcp.srcport')] || fields[header.indexOf('tcp.dstport')];
                    const udpPort = fields[header.indexOf('udp.srcport')] || fields[header.indexOf('udp.dstport')];
                    value = tcpPort || udpPort || '0';
                    break;

                case 'frame.len':
                case 'ip.len':
                case 'tcp.len':
                case 'udp.length':
                    value = this.parseNumber(value);
                    break;

                case 'frame.time_relative':
                    value = this.parseFloat(value);
                    break;

                case 'frame.protocols':
                    value = this.parseProtocol(value);
                    break;

                case 'ip.src':
                case 'ip.dst':
                    value = this.validateIP(value);
                    break;

                default:
                    if (!value || value === '') value = '0';
            }

            return value;
        });
    }

    parseNumber(value) {
        const num = parseInt(value);
        return isNaN(num) ? '0' : num.toString();
    }

    parseFloat(value) {
        const num = parseFloat(value);
        return isNaN(num) ? '0.0' : num.toString();
    }

    parseProtocol(protocols) {
        if (!protocols) return 'OTHER';
        
        const protocolStr = protocols.toLowerCase();
        
        if (protocolStr.includes('tcp')) return 'TCP';
        if (protocolStr.includes('udp')) return 'UDP';
        if (protocolStr.includes('icmp')) return 'ICMP';
        if (protocolStr.includes('http')) return 'HTTP';
        if (protocolStr.includes('https') || protocolStr.includes('ssl') || protocolStr.includes('tls')) return 'HTTPS';
        if (protocolStr.includes('dns')) return 'DNS';
        if (protocolStr.includes('ssh')) return 'SSH';
        if (protocolStr.includes('ftp')) return 'FTP';
        if (protocolStr.includes('smtp')) return 'SMTP';
        
        return 'OTHER';
    }

    validateIP(ip) {
        if (!ip || ip === '') return '0.0.0.0';
        
        // Validación básica de IP
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) return '0.0.0.0';
        
        const parts = ip.split('.');
        for (const part of parts) {
            const num = parseInt(part);
            if (num < 0 || num > 255) return '0.0.0.0';
        }
        
        return ip;
    }

    isValidRow(fields) {
        // Verificar que hay IPs válidas
        const srcIP = fields[0] || '0.0.0.0';
        const dstIP = fields[1] || '0.0.0.0';
        
        if (srcIP === '0.0.0.0' && dstIP === '0.0.0.0') return false;
        
        // Verificar que hay al menos un puerto válido
        const srcPort = parseInt(fields[2]) || 0;
        const dstPort = parseInt(fields[3]) || 0;
        
        if (srcPort === 0 && dstPort === 0) return false;
        
        return true;
    }

    async processAllPcapFiles() {
        try {
            this.log('Iniciando procesamiento de todos los archivos PCAP');

            const files = fs.readdirSync(this.inputDir)
                .filter(file => file.endsWith('.pcap'))
                .sort();

            if (files.length === 0) {
                this.log('No se encontraron archivos PCAP para procesar');
                return { processed: 0, errors: 0 };
            }

            this.log(`Encontrados ${files.length} archivos PCAP para procesar`);

            let processed = 0;
            let errors = 0;

            for (const file of files) {
                const fullPath = path.join(this.inputDir, file);
                
                try {
                    await this.processPcapToCSV(fullPath);
                    processed++;
                    
                    // Mover archivo procesado
                    await this.moveProcessedFile(fullPath);
                    
                } catch (error) {
                    this.log(`Error procesando ${file}: ${error.message}`);
                    errors++;
                }
            }

            this.log(`Procesamiento completado: ${processed} éxitos, ${errors} errores`);
            return { processed, errors };

        } catch (error) {
            this.log(`Error en procesamiento masivo: ${error.message}`);
            throw error;
        }
    }

    async moveProcessedFile(pcapFile) {
        try {
            const fileName = path.basename(pcapFile);
            const processedPath = path.join(this.processedDir, fileName);
            
            fs.renameSync(pcapFile, processedPath);
            this.log(`Archivo movido a procesados: ${fileName}`);
            
        } catch (error) {
            this.log(`Error moviendo archivo: ${error.message}`);
        }
    }

    validateOutput(csvFile) {
        try {
            if (!fs.existsSync(csvFile)) return false;
            
            const stats = fs.statSync(csvFile);
            if (stats.size === 0) return false;
            
            // Verificar que tiene al menos header + 1 fila de datos
            const content = fs.readFileSync(csvFile, 'utf8');
            const lines = content.split('\n').filter(line => line.trim());
            
            return lines.length >= 2;
            
        } catch (error) {
            this.log(`Error validando salida: ${error.message}`);
            return false;
        }
    }

    async getStats() {
        try {
            const pcapFiles = fs.readdirSync(this.inputDir)
                .filter(file => file.endsWith('.pcap'));
            
            const csvFiles = fs.readdirSync(this.outputDir)
                .filter(file => file.endsWith('.csv'));
            
            const processedFiles = fs.existsSync(this.processedDir) 
                ? fs.readdirSync(this.processedDir).filter(file => file.endsWith('.pcap'))
                : [];

            const stats = {
                pending_pcap: pcapFiles.length,
                generated_csv: csvFiles.length,
                processed_pcap: processedFiles.length,
                input_dir: this.inputDir,
                output_dir: this.outputDir
            };

            this.log(`Estadísticas: ${JSON.stringify(stats, null, 2)}`);
            return stats;

        } catch (error) {
            this.log(`Error obteniendo estadísticas: ${error.message}`);
            return {};
        }
    }
}

// Función principal
async function main() {
    const args = process.argv.slice(2);
    
    if (args.includes('--help') || args.includes('-h')) {
        console.log(`
Uso: node flow.js [opciones] [archivo_pcap]

Opciones:
  --input <archivo>    Archivo PCAP específico a procesar
  --output <archivo>   Archivo CSV de salida
  --all               Procesar todos los archivos PCAP pendientes
  --stats             Mostrar estadísticas
  --help, -h          Mostrar esta ayuda

Ejemplos:
  node flow.js --all                           # Procesar todos los archivos
  node flow.js --input capture.pcap           # Procesar archivo específico
  node flow.js --input capture.pcap --output output.csv  # Con salida específica
  node flow.js --stats                        # Mostrar estadísticas
        `);
        return;
    }

    const processor = new FlowProcessor();

    try {
        // Verificar dependencias
        await processor.checkDependencies();

        if (args.includes('--stats')) {
            await processor.getStats();
            return;
        }

        if (args.includes('--all')) {
            await processor.processAllPcapFiles();
            return;
        }

        const inputIndex = args.indexOf('--input');
        const outputIndex = args.indexOf('--output');

        if (inputIndex !== -1 && inputIndex + 1 < args.length) {
            const inputFile = args[inputIndex + 1];
            const outputFile = outputIndex !== -1 && outputIndex + 1 < args.length 
                ? args[outputIndex + 1] 
                : null;

            const result = await processor.processPcapToCSV(inputFile, outputFile);
            console.log('Procesamiento completado:', result);
            return;
        }

        // Si se pasa un archivo como primer argumento
        if (args.length > 0 && !args[0].startsWith('--')) {
            const result = await processor.processPcapToCSV(args[0]);
            console.log('Procesamiento completado:', result);
            return;
        }

        // Por defecto, procesar todos los archivos
        await processor.processAllPcapFiles();

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

// Ejecutar si es llamado directamente
if (require.main === module) {
    main().catch(error => {
        console.error('Error fatal:', error);
        process.exit(1);
    });
}

module.exports = FlowProcessor;