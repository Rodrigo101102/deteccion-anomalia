"""
Tests para la aplicación dashboard.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

User = get_user_model()


class DashboardViewsTest(TestCase):
    """Tests para las vistas del dashboard."""
    
    def setUp(self):
        """Configuración inicial para tests."""
        self.admin_user = User.objects.create_user(
            username='admin',
            password='adminpass123',
            role='admin'
        )
        
        self.regular_user = User.objects.create_user(
            username='user',
            password='userpass123',
            role='user'
        )
    
    def test_dashboard_requires_admin(self):
        """Test que el dashboard requiere permisos de admin."""
        # User not logged in
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 302)  # Redirect to login
        
        # Regular user logged in
        self.client.login(username='user', password='userpass123')
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 302)  # Access denied
    
    def test_dashboard_admin_access(self):
        """Test acceso de admin al dashboard."""
        self.client.login(username='admin', password='adminpass123')
        response = self.client.get(reverse('dashboard:index'))
        self.assertEqual(response.status_code, 200)