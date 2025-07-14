"""
Tests para la aplicación core.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from ..models import SystemConfiguration, AuditLog, SystemAlert
from ..utils import log_user_action, create_system_alert, get_system_stats

User = get_user_model()


class CustomUserModelTest(TestCase):
    """Tests para el modelo CustomUser"""
    
    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123',
            'first_name': 'Test',
            'last_name': 'User',
            'role': 'analyst'
        }
    
    def test_user_creation(self):
        """Test creación de usuario"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.role, 'analyst')
        self.assertTrue(user.check_password('testpass123'))
    
    def test_user_permissions(self):
        """Test permisos de usuario"""
        # Usuario admin
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass',
            role='admin'
        )
        self.assertTrue(admin_user.can_manage_users())
        self.assertTrue(admin_user.can_modify_config())
        self.assertTrue(admin_user.can_view_analytics())
        
        # Usuario viewer
        viewer_user = User.objects.create_user(
            username='viewer',
            email='viewer@example.com',
            password='viewerpass',
            role='viewer'
        )
        self.assertFalse(viewer_user.can_manage_users())
        self.assertFalse(viewer_user.can_modify_config())
        self.assertFalse(viewer_user.can_view_analytics())
    
    def test_update_last_activity(self):
        """Test actualización de última actividad"""
        user = User.objects.create_user(**self.user_data)
        original_activity = user.last_activity
        
        user.update_last_activity()
        user.refresh_from_db()
        
        self.assertNotEqual(user.last_activity, original_activity)


class SystemConfigurationTest(TestCase):
    """Tests para configuración del sistema"""
    
    def test_get_current_config(self):
        """Test obtener configuración actual"""
        config = SystemConfiguration.get_current_config()
        self.assertIsNotNone(config)
        self.assertEqual(config.pk, 1)
    
    def test_config_defaults(self):
        """Test valores por defecto de configuración"""
        config = SystemConfiguration.get_current_config()
        self.assertEqual(config.capture_interval, 20)
        self.assertEqual(config.capture_duration, 300)
        self.assertTrue(config.auto_start_capture)
        self.assertEqual(config.network_interface, 'eth0')


class AuditLogTest(TestCase):
    """Tests para logs de auditoría"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_log_user_action(self):
        """Test logging de acción de usuario"""
        log_user_action(
            user=self.user,
            action='login',
            description='Test login action'
        )
        
        log = AuditLog.objects.first()
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.action, 'login')
        self.assertEqual(log.description, 'Test login action')
    
    def test_audit_log_ordering(self):
        """Test ordenamiento de logs"""
        # Crear varios logs
        for i in range(3):
            log_user_action(
                user=self.user,
                action='test',
                description=f'Test action {i}'
            )
        
        logs = list(AuditLog.objects.all())
        # Debe estar ordenado por timestamp descendente
        self.assertTrue(logs[0].timestamp >= logs[1].timestamp)
        self.assertTrue(logs[1].timestamp >= logs[2].timestamp)


class SystemAlertTest(TestCase):
    """Tests para alertas del sistema"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            role='admin'
        )
    
    def test_create_system_alert(self):
        """Test creación de alerta"""
        alert = create_system_alert(
            title='Test Alert',
            description='Test alert description',
            severity='high',
            alert_type='test'
        )
        
        self.assertIsNotNone(alert)
        self.assertEqual(alert.title, 'Test Alert')
        self.assertEqual(alert.severity, 'high')
        self.assertEqual(alert.status, 'active')
    
    def test_alert_acknowledge(self):
        """Test reconocimiento de alerta"""
        alert = SystemAlert.objects.create(
            title='Test Alert',
            description='Test description',
            severity='medium',
            alert_type='test'
        )
        
        alert.acknowledge(self.user)
        alert.refresh_from_db()
        
        self.assertEqual(alert.status, 'acknowledged')
        self.assertEqual(alert.acknowledged_by, self.user)
        self.assertIsNotNone(alert.acknowledged_at)
    
    def test_alert_resolve(self):
        """Test resolución de alerta"""
        alert = SystemAlert.objects.create(
            title='Test Alert',
            description='Test description',
            severity='medium',
            alert_type='test'
        )
        
        alert.resolve(self.user)
        alert.refresh_from_db()
        
        self.assertEqual(alert.status, 'resolved')
        self.assertEqual(alert.resolved_by, self.user)
        self.assertIsNotNone(alert.resolved_at)


class CoreViewsTest(TestCase):
    """Tests para vistas de core"""
    
    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass',
            role='admin'
        )
        self.viewer_user = User.objects.create_user(
            username='viewer',
            email='viewer@example.com',
            password='viewerpass',
            role='viewer'
        )
    
    def test_home_redirect(self):
        """Test redirección desde home"""
        self.client.login(username='admin', password='adminpass')
        response = self.client.get(reverse('core:home'))
        self.assertEqual(response.status_code, 302)
    
    def test_system_config_view_admin(self):
        """Test vista de configuración para admin"""
        self.client.login(username='admin', password='adminpass')
        response = self.client.get(reverse('core:config'))
        self.assertEqual(response.status_code, 200)
    
    def test_system_config_view_viewer_denied(self):
        """Test acceso denegado a configuración para viewer"""
        self.client.login(username='viewer', password='viewerpass')
        response = self.client.get(reverse('core:config'))
        self.assertEqual(response.status_code, 403)
    
    def test_profile_view(self):
        """Test vista de perfil"""
        self.client.login(username='admin', password='adminpass')
        response = self.client.get(reverse('core:profile'))
        self.assertEqual(response.status_code, 200)
    
    def test_system_stats_api(self):
        """Test API de estadísticas"""
        self.client.login(username='admin', password='adminpass')
        response = self.client.get(reverse('core:system_stats_api'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')


class UtilsTest(TestCase):
    """Tests para utilidades"""
    
    def test_get_system_stats(self):
        """Test obtención de estadísticas del sistema"""
        stats = get_system_stats()
        
        self.assertIn('traffic', stats)
        self.assertIn('predictions', stats)
        self.assertIn('alerts', stats)
        self.assertIn('audit', stats)
        self.assertIn('users', stats)
    
    def test_create_system_alert_util(self):
        """Test utilidad de creación de alertas"""
        alert = create_system_alert(
            title='Test Util Alert',
            description='Test description',
            severity='low'
        )
        
        self.assertIsNotNone(alert)
        self.assertEqual(alert.title, 'Test Util Alert')


class MiddlewareTest(TestCase):
    """Tests para middleware personalizado"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_security_headers(self):
        """Test headers de seguridad"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/core/')
        
        # Verificar headers de seguridad
        self.assertEqual(response.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(response.get('X-Frame-Options'), 'DENY')
        self.assertEqual(response.get('X-XSS-Protection'), '1; mode=block')
    
    def test_user_activity_update(self):
        """Test actualización de actividad de usuario"""
        self.client.login(username='testuser', password='testpass123')
        
        # Hacer una request
        self.client.get('/core/')
        
        # Verificar que se actualizó la actividad
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.last_activity)
        self.assertTrue(self.user.is_active_session)