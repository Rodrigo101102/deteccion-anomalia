"""
Tests para la aplicación core.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

User = get_user_model()


class UserModelTest(TestCase):
    """Tests para el modelo de Usuario personalizado."""
    
    def test_create_user(self):
        """Test creación de usuario básico."""
        user = User.objects.create_user(
            username='testuser',
            email='test@test.com',
            password='testpass123'
        )
        
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@test.com')
        self.assertEqual(user.role, 'user')  # Default role
        self.assertFalse(user.is_admin())
    
    def test_create_admin_user(self):
        """Test creación de usuario administrador."""
        admin = User.objects.create_user(
            username='admin',
            email='admin@test.com',
            password='adminpass123',
            role='admin'
        )
        
        self.assertEqual(admin.role, 'admin')
        self.assertTrue(admin.is_admin())


class ViewsTest(TestCase):
    """Tests para las vistas de core."""
    
    def test_home_view(self):
        """Test vista principal."""
        response = self.client.get(reverse('core:home'))
        self.assertEqual(response.status_code, 200)
    
    def test_login_view(self):
        """Test vista de login."""
        response = self.client.get(reverse('core:login'))
        self.assertEqual(response.status_code, 200)
    
    def test_login_functionality(self):
        """Test funcionalidad de login."""
        user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        response = self.client.post(reverse('core:login'), {
            'username': 'testuser',
            'password': 'testpass123'
        })
        
        # Should redirect after successful login
        self.assertEqual(response.status_code, 302)