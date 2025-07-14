"""
Vistas del núcleo del sistema.
"""
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect


def home(request):
    """
    Vista principal del sistema.
    """
    if request.user.is_authenticated:
        return redirect('dashboard:index')
    return render(request, 'core/home.html')


@csrf_protect
def login_view(request):
    """
    Vista de inicio de sesión.
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'dashboard:index')
            return redirect(next_url)
        else:
            messages.error(request, 'Usuario o contraseña incorrectos.')
    
    return render(request, 'core/login.html')


@login_required
def logout_view(request):
    """
    Vista de cierre de sesión.
    """
    logout(request)
    messages.success(request, 'Sesión cerrada exitosamente.')
    return redirect('core:home')