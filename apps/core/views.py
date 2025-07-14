"""
Vistas principales del sistema.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib import messages
from django.views.generic import ListView, DetailView, CreateView, UpdateView
from django.http import JsonResponse, HttpResponseForbidden
from django.core.paginator import Paginator
from django.db.models import Q
from django.utils import timezone
from datetime import datetime, timedelta
import json

from .models import CustomUser, SystemConfiguration, AuditLog, SystemAlert
from .forms import SystemConfigurationForm, UserProfileForm
from .decorators import admin_required, analyst_required
from .utils import log_user_action, get_system_stats


def custom_404(request, exception):
    """Vista personalizada para error 404"""
    return render(request, 'errors/404.html', status=404)


def custom_500(request):
    """Vista personalizada para error 500"""
    return render(request, 'errors/500.html', status=500)


@login_required
def home_view(request):
    """Vista principal que redirige al dashboard"""
    return redirect('dashboard:index')


class SystemConfigurationView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    """Vista para configuración del sistema"""
    model = SystemConfiguration
    form_class = SystemConfigurationForm
    template_name = 'core/system_config.html'
    success_url = '/core/config/'
    
    def test_func(self):
        return self.request.user.can_modify_config()
    
    def get_object(self, queryset=None):
        return SystemConfiguration.get_current_config()
    
    def form_valid(self, form):
        form.instance.updated_by = self.request.user
        
        # Log de auditoría
        log_user_action(
            user=self.request.user,
            action='config_change',
            description='Configuración del sistema actualizada',
            request=self.request
        )
        
        messages.success(self.request, 'Configuración actualizada exitosamente.')
        return super().form_valid(form)


@login_required
def user_profile_view(request):
    """Vista para perfil de usuario"""
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Perfil actualizado exitosamente.')
            return redirect('core:profile')
    else:
        form = UserProfileForm(instance=request.user)
    
    return render(request, 'core/profile.html', {'form': form})


class AuditLogListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    """Vista para logs de auditoría"""
    model = AuditLog
    template_name = 'core/audit_logs.html'
    context_object_name = 'logs'
    paginate_by = 50
    
    def test_func(self):
        return self.request.user.can_view_analytics()
    
    def get_queryset(self):
        queryset = AuditLog.objects.all()
        
        # Filtros
        action = self.request.GET.get('action')
        user_id = self.request.GET.get('user')
        date_from = self.request.GET.get('date_from')
        date_to = self.request.GET.get('date_to')
        
        if action:
            queryset = queryset.filter(action=action)
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        if date_from:
            try:
                date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__gte=date_from)
            except ValueError:
                pass
        if date_to:
            try:
                date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__lte=date_to)
            except ValueError:
                pass
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['action_choices'] = AuditLog.ACTION_CHOICES
        context['users'] = CustomUser.objects.all().order_by('username')
        return context


class SystemAlertListView(LoginRequiredMixin, ListView):
    """Vista para alertas del sistema"""
    model = SystemAlert
    template_name = 'core/alerts.html'
    context_object_name = 'alerts'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = SystemAlert.objects.all()
        
        # Filtros
        severity = self.request.GET.get('severity')
        status = self.request.GET.get('status')
        
        if severity:
            queryset = queryset.filter(severity=severity)
        if status:
            queryset = queryset.filter(status=status)
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['severity_choices'] = SystemAlert.SEVERITY_CHOICES
        context['status_choices'] = SystemAlert.STATUS_CHOICES
        
        # Estadísticas de alertas
        context['alert_stats'] = {
            'total': SystemAlert.objects.count(),
            'active': SystemAlert.objects.filter(status='active').count(),
            'critical': SystemAlert.objects.filter(severity='critical', status='active').count(),
            'high': SystemAlert.objects.filter(severity='high', status='active').count(),
        }
        
        return context


@login_required
def alert_action_view(request, alert_id):
    """Vista para acciones sobre alertas"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
    alert = get_object_or_404(SystemAlert, id=alert_id)
    action = request.POST.get('action')
    
    try:
        if action == 'acknowledge':
            alert.acknowledge(request.user)
            message = 'Alerta reconocida exitosamente.'
        elif action == 'resolve':
            alert.resolve(request.user)
            message = 'Alerta resuelta exitosamente.'
        elif action == 'false_positive':
            alert.mark_false_positive(request.user)
            message = 'Alerta marcada como falso positivo.'
        else:
            return JsonResponse({'error': 'Acción no válida'}, status=400)
        
        # Log de auditoría
        log_user_action(
            user=request.user,
            action='alert_action',
            description=f'Acción {action} en alerta {alert.title}',
            request=request,
            additional_data={'alert_id': alert_id, 'action': action}
        )
        
        return JsonResponse({'success': True, 'message': message})
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def system_stats_api(request):
    """API para estadísticas del sistema"""
    try:
        stats = get_system_stats()
        return JsonResponse(stats)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@admin_required
def users_management_view(request):
    """Vista para gestión de usuarios"""
    search = request.GET.get('search', '')
    role_filter = request.GET.get('role', '')
    
    users = CustomUser.objects.all()
    
    if search:
        users = users.filter(
            Q(username__icontains=search) |
            Q(email__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search)
        )
    
    if role_filter:
        users = users.filter(role=role_filter)
    
    paginator = Paginator(users, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'search': search,
        'role_filter': role_filter,
        'role_choices': CustomUser.ROLE_CHOICES,
    }
    
    return render(request, 'core/users_management.html', context)


@admin_required
def toggle_user_status(request, user_id):
    """Vista para activar/desactivar usuarios"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
    user = get_object_or_404(CustomUser, id=user_id)
    
    if user == request.user:
        return JsonResponse({'error': 'No puedes desactivarte a ti mismo'}, status=400)
    
    user.is_active = not user.is_active
    user.save()
    
    action = 'activado' if user.is_active else 'desactivado'
    
    # Log de auditoría
    log_user_action(
        user=request.user,
        action='user_modified',
        description=f'Usuario {user.username} {action}',
        request=request,
        additional_data={'target_user': user.username, 'action': action}
    )
    
    return JsonResponse({
        'success': True,
        'message': f'Usuario {action} exitosamente',
        'is_active': user.is_active
    })


@login_required
def dashboard_data_api(request):
    """API para datos del dashboard"""
    try:
        # Estadísticas recientes
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        
        from apps.traffic.models import TraficoRed
        from apps.prediction.models import ModeloPrediccion
        
        data = {
            'traffic_last_24h': TraficoRed.objects.filter(fecha_captura__gte=last_24h).count(),
            'anomalies_last_24h': TraficoRed.objects.filter(
                fecha_captura__gte=last_24h,
                label='ANOMALO'
            ).count(),
            'predictions_last_24h': ModeloPrediccion.objects.filter(
                fecha_prediccion__gte=last_24h
            ).count(),
            'active_alerts': SystemAlert.objects.filter(status='active').count(),
            'critical_alerts': SystemAlert.objects.filter(
                status='active',
                severity='critical'
            ).count(),
        }
        
        return JsonResponse(data)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)