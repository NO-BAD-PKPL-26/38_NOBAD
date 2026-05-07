from django.shortcuts import render, redirect
# from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
# from django.utils import timezone
# from django.db import transaction as db_transaction
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from .models import User, Transaction 
from .models import LoginAttempt , Account 
from .forms import LoginForm, RegisterForm
from .forms import TransferForm, TopUpForm, AccountSearchForm
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


# ── Nasabah (Orang 3) ────────────────────────────────────────────────────────
# Fitur: Dashboard, Mutasi, Cari Rekening
# TC-SQLi-02 (search injection), TC-SQLi-03 (code review)
# Test: MT-1, MT-2, TC-CI-03, TC-SQLi-02, TC-SQLi-03

@login_required
@role_required('nasabah')
def nasabah_dashboard(request):
    # [Orang 3] DASHBOARD: tampilkan saldo + 5 transaksi terakhir
    # Least privilege: hanya bisa akses dashboard milik sendiri (via @role_required)
    account = get_or_create_account(request.user)  # Ambil/buat akun nasabah dari user
    # Query transaksi: filter masuk (to_account) ATAU keluar (from_account)
    # PENTING: pakai ORM .filter() BUKAN raw SQL — aman dari SQL injection (TC-SQLi-03)
    recent = (
        Transaction.objects.filter(from_account=account) |  # Transaksi keluar (debit)
        Transaction.objects.filter(to_account=account)      # Transaksi masuk (kredit)
    ).order_by('-created_at')[:5]  # Urutkan terbaru dulu, ambil 5 saja
    # Return: render template dengan context account & 5 transaksi terakhir
    return render(request, 'nasabah/dashboard.html', {
        'account': account,
        'transactions': recent  # Untuk ditampilkan di template
    })


# untuk transfer view


@login_required
@role_required('nasabah')
def mutasi_view(request):
    # [Orang 3] MUTASI: tampilkan SEMUA riwayat transaksi nasabah (masuk & keluar)
    # Berbeda dengan dashboard yg hanya 5 terakhir, mutasi tampil semua history
    account = get_or_create_account(request.user)  # Ambil akun nasabah
    # Query ORM — parameterized otomatis, tidak bisa SQL injection (TC-SQLi-03)
    transactions = (
        Transaction.objects.filter(from_account=account) |  # Transaksi keluar (debit)
        Transaction.objects.filter(to_account=account)      # Transaksi masuk (kredit)
    ).order_by('-created_at')  # Urutkan terbaru dulu (SEMUA, bukan limited)
    # Return: render template mutasi dengan account & semua transaksi
    return render(request, 'nasabah/mutasi.html', {
        'account': account,
        'transactions': transactions  # List lengkap transaksi untuk tabel
    })


@login_required
@role_required('nasabah')
def search_account_view(request):
    # [Orang 3] CARI REKENING: search bar untuk cari rekening orang lain
    # TC-SQLi-02: VULNERABLE = raw SQL concat (UNION injection possible)
    # TC-SQLi-02: SECURE = AccountSearchForm + ORM Q objects (parameterized)
    # Input method: GET (REST convention untuk search/read-only)
    form = AccountSearchForm(request.GET or None)  # Ambil form dari GET params
    results = []  # Hasil search (empty jika belum cari atau invalid)
    query = ''    # Search query yang user input
    # Validasi form — jika valid, ambil query & cari via ORM
    if form.is_valid():
        # Ambil query dari form (sudah divalidasi via validate_no_injection)
        # validate_no_injection() blok: <script, javascript:, {}, {%, dll (CWE-79, CWE-94)
        query = form.cleaned_data.get('query', '')
        if query:  # Jika ada query (tidak kosong)
            # ORM Q objects dengan icontains — PARAMETERIZED query otomatis
            # AMAN dari UNION injection: ' UNION SELECT username, password ... --
            results = Account.objects.filter(
                Q(account_number__icontains=query) |    # Cari by nomor rekening
                Q(user__first_name__icontains=query) |  # Cari by nama depan
                Q(user__last_name__icontains=query),    # Cari by nama belakang
                is_active=True  # Hanya rekening aktif
            ).exclude(user=request.user) \
            .select_related('user')  # Optimize: ambil user data sekalian
            results = results[:10]  # Limit 10 hasil (untuk performa)
    # Return: render template dengan form, results, & query
    return render(request, 'nasabah/search_account.html', {
        'form': form,       # Form untuk ditampilkan di template
        'results': results, # List hasil search
        'query': query      # Query yang dicari (untuk info di template)
    })

# ── Teller ────────────────────────────────────────────────────────────────────












# ── Supervisor ────────────────────────────────────────────────────────────────




