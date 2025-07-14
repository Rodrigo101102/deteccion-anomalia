"""
Configuración para tests.
"""

from .base import *

# Base de datos en memoria para tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Password hashers más rápidos para tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Cache en memoria para tests
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# Email backend para tests
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Celery en modo síncrono para tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

# Logging silencioso para tests
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'null': {
            'class': 'logging.NullHandler',
        },
    },
    'root': {
        'handlers': ['null'],
    },
}

# Media files en directorio temporal
import tempfile
MEDIA_ROOT = tempfile.mkdtemp()

# Deshabilitar migraciones para tests más rápidos
class DisableMigrations:
    def __contains__(self, item):
        return True
    
    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# Configuración de test específica
TEST_RUNNER = 'django.test.runner.DiscoverRunner'

# Configuraciones específicas para testing
CAPTURE_SETTINGS.update({
    'DURATION': 1,  # Duraciones muy cortas para tests
    'INTERVAL': 1,
    'AUTO_START': False,  # No iniciar automáticamente en tests
})

ML_SETTINGS.update({
    'RETRAIN_INTERVAL': 10,  # Intervalos cortos para tests
    'BATCH_SIZE': 10,
})

# Deshabilitar throttling en tests
REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES'] = []

# Debug deshabilitado en tests
DEBUG = False

# Secret key fija para tests
SECRET_KEY = 'test-secret-key-for-testing-only'