from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    # Nasabah
    path('nasabah/', views.nasabah_dashboard, name='nasabah_dashboard'),  # dashboard dengan saldo & 5 tx terakhir
    path('nasabah/transfer/', views.transfer_view, name='transfer'),
    path('nasabah/mutasi/', views.mutasi_view, name='mutasi'),  # riwayat semua transaksi
    path('nasabah/cari-rekening/', views.search_account_view, name='search_account'),  # cari rekening orang lain
    # Teller
    path('teller/', views.teller_dashboard, name='teller_dashboard'),
    path('teller/topup/', views.topup_view, name='topup'),
    # Supervisor
    path('supervisor/', views.supervisor_dashboard, name='supervisor_dashboard'),
    path('supervisor/accounts/', views.manage_accounts_view, name='manage_accounts'),
    path('supervisor/accounts/<int:account_id>/toggle/', views.toggle_account_view, name='toggle_account'),
]