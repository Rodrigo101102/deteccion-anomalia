"""
Tests para la aplicación traffic.
"""
from django.test import TestCase
from .models import TraficoRed, CaptureSession


class TraficoRedModelTest(TestCase):
    """Tests para el modelo TraficoRed."""
    
    def test_create_traffic_record(self):
        """Test creación de registro de tráfico."""
        traffic = TraficoRed.objects.create(
            src_ip='192.168.1.100',
            dst_ip='10.0.0.1',
            src_port=12345,
            dst_port=80,
            protocol='TCP',
            packet_size=1024,
            duration=5.5,
            total_fwd_packets=10,
            total_backward_packets=8
        )
        
        self.assertEqual(traffic.src_ip, '192.168.1.100')
        self.assertEqual(traffic.protocol, 'TCP')
        self.assertEqual(traffic.label, 'PENDIENTE')  # Default
        self.assertFalse(traffic.procesado)  # Default
    
    def test_flow_key_property(self):
        """Test propiedad flow_key."""
        traffic = TraficoRed.objects.create(
            src_ip='192.168.1.100',
            dst_ip='10.0.0.1',
            src_port=12345,
            dst_port=80,
            protocol='TCP',
            packet_size=1024,
            duration=5.5,
            total_fwd_packets=10,
            total_backward_packets=8
        )
        
        expected_key = '192.168.1.100:12345-10.0.0.1:80-TCP'
        self.assertEqual(traffic.flow_key, expected_key)