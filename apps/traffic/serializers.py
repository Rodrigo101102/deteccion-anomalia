"""
Serializadores para la API REST de tráfico.
"""

from rest_framework import serializers
from .models import TraficoRed, CaptureSession, TrafficStatistics


class TraficoRedSerializer(serializers.ModelSerializer):
    """Serializador para modelo TraficoRed"""
    
    traffic_direction = serializers.ReadOnlyField()
    is_anomaly = serializers.ReadOnlyField()
    is_private_source = serializers.ReadOnlyField()
    is_private_destination = serializers.ReadOnlyField()
    flow_identifier = serializers.SerializerMethodField()
    
    class Meta:
        model = TraficoRed
        fields = [
            'id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'packet_size', 'duration', 'flow_bytes_per_sec', 'flow_packets_per_sec',
            'total_fwd_packets', 'total_backward_packets',
            'label', 'confidence_score', 'fecha_captura', 'procesado',
            'traffic_direction', 'is_anomaly', 'is_private_source', 'is_private_destination',
            'flow_identifier', 'archivo_origen'
        ]
        read_only_fields = ['id', 'fecha_captura', 'updated_at']
    
    def get_flow_identifier(self, obj):
        """Obtiene el identificador del flujo"""
        return obj.get_flow_identifier()


class TraficoRedCreateSerializer(serializers.ModelSerializer):
    """Serializador para crear registros de tráfico"""
    
    class Meta:
        model = TraficoRed
        fields = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'packet_size', 'duration', 'flow_bytes_per_sec', 'flow_packets_per_sec',
            'total_fwd_packets', 'total_backward_packets',
            'archivo_origen'
        ]
    
    def validate_src_port(self, value):
        """Valida puerto origen"""
        if not 0 <= value <= 65535:
            raise serializers.ValidationError("El puerto debe estar entre 0 y 65535")
        return value
    
    def validate_dst_port(self, value):
        """Valida puerto destino"""
        if not 0 <= value <= 65535:
            raise serializers.ValidationError("El puerto debe estar entre 0 y 65535")
        return value
    
    def validate_duration(self, value):
        """Valida duración"""
        if value < 0:
            raise serializers.ValidationError("La duración no puede ser negativa")
        return value


class CaptureSessionSerializer(serializers.ModelSerializer):
    """Serializador para sesiones de captura"""
    
    duration_actual = serializers.ReadOnlyField()
    started_by_username = serializers.CharField(source='started_by.username', read_only=True)
    
    class Meta:
        model = CaptureSession
        fields = [
            'id', 'session_id', 'interface', 'duration', 'status',
            'pcap_file_path', 'csv_file_path', 'packets_captured', 'bytes_captured',
            'error_message', 'started_by_username', 'created_at', 'started_at',
            'completed_at', 'duration_actual'
        ]
        read_only_fields = [
            'id', 'session_id', 'status', 'pcap_file_path', 'csv_file_path',
            'packets_captured', 'bytes_captured', 'error_message',
            'created_at', 'started_at', 'completed_at'
        ]


class TrafficStatisticsSerializer(serializers.ModelSerializer):
    """Serializador para estadísticas de tráfico"""
    
    anomaly_percentage = serializers.ReadOnlyField()
    datetime = serializers.SerializerMethodField()
    
    class Meta:
        model = TrafficStatistics
        fields = [
            'id', 'date', 'hour', 'datetime', 'total_packets', 'total_bytes',
            'unique_flows', 'tcp_packets', 'udp_packets', 'icmp_packets',
            'other_packets', 'inbound_packets', 'outbound_packets',
            'internal_packets', 'normal_packets', 'anomalous_packets',
            'suspicious_packets', 'anomaly_percentage', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_datetime(self, obj):
        """Combina fecha y hora en datetime"""
        from datetime import datetime, time
        return datetime.combine(obj.date, time(obj.hour, 0)).isoformat()


class TrafficSummarySerializer(serializers.Serializer):
    """Serializador para resumen de tráfico"""
    
    total_records = serializers.IntegerField()
    anomalous_records = serializers.IntegerField()
    normal_records = serializers.IntegerField()
    unprocessed_records = serializers.IntegerField()
    anomaly_percentage = serializers.FloatField()
    
    # Estadísticas por protocolo
    tcp_count = serializers.IntegerField()
    udp_count = serializers.IntegerField()
    icmp_count = serializers.IntegerField()
    other_count = serializers.IntegerField()
    
    # Estadísticas de tiempo
    first_capture = serializers.DateTimeField()
    last_capture = serializers.DateTimeField()
    
    # Top elementos
    top_source_ips = serializers.ListField()
    top_destination_ips = serializers.ListField()
    top_ports = serializers.ListField()


class FlowAnalysisSerializer(serializers.Serializer):
    """Serializador para análisis de flujos"""
    
    flow_id = serializers.CharField()
    src_ip = serializers.IPAddressField()
    dst_ip = serializers.IPAddressField()
    src_port = serializers.IntegerField()
    dst_port = serializers.IntegerField()
    protocol = serializers.CharField()
    
    # Métricas del flujo
    total_packets = serializers.IntegerField()
    total_bytes = serializers.IntegerField()
    duration = serializers.FloatField()
    avg_packet_size = serializers.FloatField()
    packets_per_second = serializers.FloatField()
    bytes_per_second = serializers.FloatField()
    
    # Análisis de anomalías
    anomaly_score = serializers.FloatField()
    is_anomalous = serializers.BooleanField()
    anomaly_reason = serializers.CharField()
    
    # Información adicional
    direction = serializers.CharField()
    is_internal = serializers.BooleanField()
    risk_level = serializers.CharField()


class BulkTrafficCreateSerializer(serializers.Serializer):
    """Serializador para creación masiva de registros de tráfico"""
    
    traffic_data = TraficoRedCreateSerializer(many=True)
    source_file = serializers.CharField(max_length=255, required=False)
    
    def validate_traffic_data(self, value):
        """Valida datos de tráfico"""
        if not value:
            raise serializers.ValidationError("Se requiere al menos un registro de tráfico")
        
        if len(value) > 10000:
            raise serializers.ValidationError("Máximo 10,000 registros por lote")
        
        return value
    
    def create(self, validated_data):
        """Crea registros de tráfico en lote"""
        traffic_data = validated_data['traffic_data']
        source_file = validated_data.get('source_file', '')
        
        created_records = []
        for record_data in traffic_data:
            record_data['archivo_origen'] = source_file
            record = TraficoRed.objects.create(**record_data)
            created_records.append(record)
        
        return {
            'created_count': len(created_records),
            'created_records': created_records
        }