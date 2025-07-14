"""
Decoradores personalizados para el sistema.
"""

from functools import wraps
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
import logging

logger = logging.getLogger(__name__)


def admin_required(view_func):
    """Decorador que requiere permisos de administrador"""
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        if not hasattr(request.user, 'role') or request.user.role != 'admin':
            logger.warning(f"Acceso denegado a {request.user.username} en {request.path}")
            raise PermissionDenied("Se requieren permisos de administrador")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def analyst_required(view_func):
    """Decorador que requiere permisos de analista o superior"""
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        user_role = getattr(request.user, 'role', 'viewer')
        if user_role not in ['admin', 'analyst']:
            logger.warning(f"Acceso denegado a {request.user.username} en {request.path}")
            raise PermissionDenied("Se requieren permisos de analista")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def operator_required(view_func):
    """Decorador que requiere permisos de operador o superior"""
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        user_role = getattr(request.user, 'role', 'viewer')
        if user_role not in ['admin', 'analyst', 'operator']:
            logger.warning(f"Acceso denegado a {request.user.username} en {request.path}")
            raise PermissionDenied("Se requieren permisos de operador")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def api_key_required(view_func):
    """Decorador para autenticación por API key"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.GET.get('api_key')
        
        if not api_key:
            return HttpResponseForbidden("API key requerida")
        
        # Verificar API key (aquí implementarías tu lógica de validación)
        if not validate_api_key(api_key):
            return HttpResponseForbidden("API key inválida")
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def validate_api_key(api_key):
    """Valida una API key (implementar según necesidades)"""
    # Implementar validación real de API key
    # Por ahora, una validación básica
    from django.conf import settings
    valid_keys = getattr(settings, 'API_KEYS', [])
    return api_key in valid_keys


def rate_limit(max_requests=100, window_seconds=60):
    """Decorador para rate limiting"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            from django.core.cache import cache
            from django.utils import timezone
            from .utils import get_client_ip
            
            client_ip = get_client_ip(request)
            cache_key = f"rate_limit_{client_ip}_{view_func.__name__}"
            
            # Obtener el contador actual
            current_count = cache.get(cache_key, 0)
            
            if current_count >= max_requests:
                return HttpResponseForbidden("Rate limit exceeded")
            
            # Incrementar contador
            cache.set(cache_key, current_count + 1, window_seconds)
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def log_action(action_type, description=None):
    """Decorador para logging automático de acciones"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            from .utils import log_user_action
            
            try:
                result = view_func(request, *args, **kwargs)
                
                if request.user.is_authenticated:
                    desc = description or f"Ejecutó {view_func.__name__}"
                    log_user_action(
                        user=request.user,
                        action=action_type,
                        description=desc,
                        request=request
                    )
                
                return result
            except Exception as e:
                if request.user.is_authenticated:
                    log_user_action(
                        user=request.user,
                        action='system_error',
                        description=f"Error en {view_func.__name__}: {str(e)}",
                        request=request
                    )
                raise
        return _wrapped_view
    return decorator


def cache_result(timeout=300):
    """Decorador para cachear resultados de vistas"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            from django.core.cache import cache
            import hashlib
            
            # Crear clave de cache basada en parámetros
            cache_key_data = f"{view_func.__name__}_{args}_{kwargs}_{request.GET.urlencode()}"
            cache_key = hashlib.md5(cache_key_data.encode()).hexdigest()
            
            # Intentar obtener del cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Ejecutar vista y cachear resultado
            result = view_func(request, *args, **kwargs)
            cache.set(cache_key, result, timeout)
            
            return result
        return _wrapped_view
    return decorator