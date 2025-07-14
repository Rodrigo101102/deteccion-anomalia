"""
WSGI config for anomalia_detection project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'anomalia_detection.settings')

application = get_wsgi_application()