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

    path('nasabah/mutasi/', views.mutasi_view, name='mutasi'),  # riwayat semua transaksi
    path('nasabah/cari-rekening/', views.search_account_view, name='search_account'),  # cari rekening orang lain
    # Teller
    



    # Supervisor
    


    
]