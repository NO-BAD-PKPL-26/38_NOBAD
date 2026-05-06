from django.shortcuts import render, redirect
# from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
# from django.utils import timezone
# from django.db import transaction as db_transaction
from django.core.exceptions import PermissionDenied
# from django.db.models import Q
# from .models import User, Transaction 
from .models import LoginAttempt , Account 
from .forms import LoginForm, RegisterForm
# from .forms import TransferForm, TopUpForm, AccountSearchForm
from .middleware import get_client_ip
import random


def get_or_create_account(user):
    account, created = Account.objects.get_or_create(
        user=user,
        defaults={
            'account_number': str(random.randint(1000000000, 9999999999)),
            'balance': 0,
        }
    )
    return account 


def role_required(*roles):
    """Least privilege decorator (CWE-272)"""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            if request.user.role not in roles and not request.user.is_superuser:
                raise PermissionDenied
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# ── Auth ──────────────────────────────────────────────────────────────────────

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(request.POST)
        ip = get_client_ip(request)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                LoginAttempt.objects.create(ip_address=ip, username=username, success=True)
                login(request, user)
                return redirect('dashboard')
            else:
                LoginAttempt.objects.create(ip_address=ip, username=username, success=False)
                # TC-BA-05: same error message for wrong username OR wrong password
                messages.error(request, 'Username atau password salah.')
    return render(request, 'auth/login.html', {'form': form})


def register_view(request):
    form = RegisterForm()
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.role = 'nasabah'
            user.phone = form.cleaned_data['phone']
            user.save()
            get_or_create_account(user)
            messages.success(request, 'Registrasi berhasil! Silakan login.')
            return redirect('login')
    return render(request, 'auth/register.html', {'form': form})


def logout_view(request):
    # POST only to prevent CSRF logout attack
    if request.method == 'POST':
        logout(request)
        messages.info(request, 'Anda telah logout.')
    return redirect('login')


# ── Dashboard router ──────────────────────────────────────────────────────────

@login_required
def dashboard_view(request):
    if request.user.role == 'nasabah':
        return redirect('nasabah_dashboard')
    elif request.user.role == 'teller':
        return redirect('teller_dashboard')
    elif request.user.role == 'supervisor':
        return redirect('supervisor_dashboard')
    return redirect('login')


# ── Nasabah ───────────────────────────────────────────────────────────────────












# ── Teller ────────────────────────────────────────────────────────────────────












# ── Supervisor ────────────────────────────────────────────────────────────────




