"""
Middleware personalizado para el sistema.
"""

from django.utils import timezone
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.conf import settings
from django.http import HttpResponseForbidden
import logging

from .models import AuditLog
from .utils import get_client_ip, log_user_action

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """Middleware de seguridad personalizado"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Procesar request antes de la vista
        self.process_request(request)
        
        response = self.get_response(request)
        
        # Procesar response después de la vista
        self.process_response(request, response)
        
        return response
    
    def process_request(self, request):
        """Procesa la request antes de llegar a la vista"""
        
        # Actualizar última actividad del usuario
        if request.user.is_authenticated:
            request.user.update_last_activity()
            request.user.is_active_session = True
            request.user.save(update_fields=['last_activity', 'is_active_session'])
        
        # Log de acceso para URLs importantes
        if self.should_log_access(request):
            self.log_access(request)
    
    def process_response(self, request, response):
        """Procesa la response después de la vista"""
        
        # Añadir headers de seguridad
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy para desarrollo
        if settings.DEBUG:
            response['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https:; "
                "font-src 'self' https://cdn.jsdelivr.net;"
            )
        
        return response
    
    def should_log_access(self, request):
        """Determina si debe registrar el acceso"""
        sensitive_paths = [
            '/admin/',
            '/core/config/',
            '/core/users/',
            '/api/',
        ]
        
        return any(request.path.startswith(path) for path in sensitive_paths)
    
    def log_access(self, request):
        """Registra acceso a URLs sensibles"""
        try:
            if request.user.is_authenticated:
                log_user_action(
                    user=request.user,
                    action='page_access',
                    description=f'Acceso a {request.path}',
                    request=request
                )
        except Exception as e:
            logger.error(f"Error logging access: {e}")


class SessionTimeoutMiddleware:
    """Middleware para timeout de sesión"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        if request.user.is_authenticated:
            # Verificar si la sesión ha expirado
            if self.is_session_expired(request):
                logout(request)
                return redirect('login')
        
        response = self.get_response(request)
        return response
    
    def is_session_expired(self, request):
        """Verifica si la sesión ha expirado"""
        if not hasattr(request.user, 'last_activity'):
            return False
        
        if request.user.last_activity is None:
            return False
        
        # Timeout de 2 horas por defecto
        timeout_minutes = getattr(settings, 'SESSION_TIMEOUT_MINUTES', 120)
        timeout_delta = timezone.timedelta(minutes=timeout_minutes)
        
        return timezone.now() - request.user.last_activity > timeout_delta


class AuditLoggingMiddleware:
    """Middleware para logging automático de auditoría"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Log automático para ciertas acciones
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            self.log_modification(request, response)
        
        return response
    
    def log_modification(self, request, response):
        """Registra modificaciones automáticamente"""
        try:
            if not request.user.is_authenticated:
                return
            
            # Solo log si la operación fue exitosa
            if 200 <= response.status_code < 300:
                action_map = {
                    'POST': 'create',
                    'PUT': 'update',
                    'PATCH': 'update',
                    'DELETE': 'delete'
                }
                
                action = action_map.get(request.method, 'modification')
                
                log_user_action(
                    user=request.user,
                    action=action,
                    description=f'{request.method} request to {request.path}',
                    request=request,
                    additional_data={'status_code': response.status_code}
                )
        except Exception as e:
            logger.error(f"Error in audit logging: {e}")


class RateLimitMiddleware:
    """Middleware básico de rate limiting"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.rate_limit_storage = {}
    
    def __call__(self, request):
        client_ip = get_client_ip(request)
        
        # Rate limiting básico por IP
        if self.is_rate_limited(client_ip):
            return HttpResponseForbidden("Rate limit exceeded")
        
        response = self.get_response(request)
        return response
    
    def is_rate_limited(self, ip):
        """Verifica si la IP está rate limited"""
        now = timezone.now()
        
        # Limpiar entradas antiguas
        cutoff = now - timezone.timedelta(minutes=1)
        self.rate_limit_storage = {
            ip: timestamps for ip, timestamps in self.rate_limit_storage.items()
            if any(ts > cutoff for ts in timestamps)
        }
        
        # Verificar rate limit (100 requests por minuto por IP)
        if ip not in self.rate_limit_storage:
            self.rate_limit_storage[ip] = []
        
        recent_requests = [
            ts for ts in self.rate_limit_storage[ip]
            if ts > cutoff
        ]
        
        if len(recent_requests) >= 100:
            return True
        
        # Añadir timestamp actual
        self.rate_limit_storage[ip] = recent_requests + [now]
        return False