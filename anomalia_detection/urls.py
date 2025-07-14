"""
URL configuration for anomalia_detection project.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # Redirect root to dashboard
    path('', RedirectView.as_view(url='/dashboard/', permanent=False)),
    
    # Authentication
    path('accounts/login/', auth_views.LoginView.as_view(template_name='auth/login.html'), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(template_name='auth/logout.html'), name='logout'),
    
    # Apps URLs
    path('dashboard/', include('apps.dashboard.urls')),
    path('api/traffic/', include('apps.traffic.urls')),
    path('api/prediction/', include('apps.prediction.urls')),
    path('core/', include('apps.core.urls')),
    
    # API Root
    path('api/', include('rest_framework.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug toolbar
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns

# Custom error handlers
handler404 = 'apps.core.views.custom_404'
handler500 = 'apps.core.views.custom_500'

# Admin site configuration
admin.site.site_header = 'Sistema de Detección de Anomalías'
admin.site.site_title = 'Admin Panel'
admin.site.index_title = 'Administración del Sistema'