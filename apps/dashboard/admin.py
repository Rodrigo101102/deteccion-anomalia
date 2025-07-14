from django.contrib import admin
from .models import DashboardWidget, UserDashboardPreference


@admin.register(DashboardWidget)
class DashboardWidgetAdmin(admin.ModelAdmin):
    list_display = ['name', 'widget_type', 'position_x', 'position_y', 'width', 'height', 'is_active']
    list_filter = ['widget_type', 'is_active']
    search_fields = ['name']
    list_editable = ['is_active']


@admin.register(UserDashboardPreference)
class UserDashboardPreferenceAdmin(admin.ModelAdmin):
    list_display = ['user', 'theme', 'default_view', 'auto_refresh', 'refresh_interval']
    list_filter = ['theme', 'default_view', 'auto_refresh']
    search_fields = ['user__username', 'user__email']