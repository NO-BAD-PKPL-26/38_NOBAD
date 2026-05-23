from django.test import TestCase, Client
from django.urls import reverse
from core.models import User, Account, Transaction
from django.utils import timezone

class BankingSecurityTests(TestCase):
    def setUp(self):
        # SETUP DATA: Dijalankan sebelum setiap fungsi test dieksekusi.
        # Membuat dua tipe user dan rekening untuk mensimulasikan skenario akses.
        self.nasabah_user = User.objects.create_user(username='nasabah_bion', password='password123', role='nasabah')
        self.teller_user = User.objects.create_user(username='teller_bion', password='password123', role='teller')
        self.nasabah_acc = Account.objects.create(user=self.nasabah_user, account_number='11112222', balance=500000)
        self.teller_acc = Account.objects.create(user=self.teller_user, account_number='33334444', balance=0)
        
        # Inisialisasi web client bawaan test Django
        self.client = Client()


    # 1. BROKEN AUTHENTICATION ======
    
    def test_least_privilege_access(self):
        """Nasabah tidak bisa akses dashboard Teller"""
        # 1. Login menggunakan akun nasabah biasa
        self.client.login(username='nasabah_bion', password='password123')
        
        # 2. Nasabah mencoba mengakses URL dashboard milik teller
        response = self.client.get(reverse('teller_dashboard'))
        
        # 3. ASSERTION: Sistem harus menolak akses tersebut.
        # Status code 403 (Forbidden) membuktikan decorator @role_required bekerja dengan benar.
        self.assertEqual(response.status_code, 403)


    def test_generic_login_error_message(self):
        """Pesan error login tidak membocorkan username yang valid"""
        # 1. Simulasi login dengan username yang memang TIDAK ADA di database
        res_wrong_user = self.client.post(reverse('login'), {'username': 'ngasal', 'password': 'password123'})
        
        # 2. Simulasi login dengan username yang ADA, tapi passwordnya SALAH
        res_wrong_pass = self.client.post(reverse('login'), {'username': 'nasabah_bion', 'password': 'salah'})
        
        # 3. Mengambil isi pesan error (messages) dari response HTML
        msg_user = list(res_wrong_user.context['messages'])[0].message
        msg_pass = list(res_wrong_pass.context['messages'])[0].message
        
        # 4. ASSERTION: Kedua kondisi gagal login harus menghasilkan teks error yang persis sama.
        # Jika pesannya beda, hacker bisa melakukan "Enumeration" untuk menebak daftar username di web.
        self.assertEqual(msg_user, msg_pass)
        self.assertEqual(msg_user, 'Username atau password salah.')

    def test_unauthenticated_user_redirected_to_login(self):
        """Memastikan user yang belum login ditolak dari halaman internal"""
        # User mencoba mengakses dashboard tanpa login
        response = self.client.get(reverse('nasabah_dashboard'))
        
        # Harus diarahkan (HTTP 302 Redirect) kembali ke halaman login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_logout_only_accepts_post(self):
        """Memastikan logout hanya bisa dilakukan via POST request"""
        self.client.login(username='nasabah_bion', password='password123')
        
        # Mengakses endpoint logout dengan GET request (misal dari jebakan link)
        response = self.client.get(reverse('logout'))
        
        # Cek apakah user masih memiliki akses (session belum dihancurkan)
        dash_response = self.client.get(reverse('nasabah_dashboard'))
        
        # Status 200 berarti user masih bisa melihat halaman dashboard (belum ter-logout)
        self.assertEqual(dash_response.status_code, 200)


    # 2. CODE INJECTION / XSS ====
    
    def test_xss_prevention_on_transaction_history(self):
        """Input tag script di-escape di halaman mutasi"""
        # 1. Siapkan payload XSS berbahaya. Panjangnya < 30 agar lolos filter truncatechars di template.
        xss_payload = "<script>alert(1)</script>" 
        
        # 2. Masukkan payload ke database melalui kolom keterangan (description) transaksi
        Transaction.objects.create(
            from_account=self.nasabah_acc,
            to_account=self.teller_acc,
            transaction_type='transfer',
            amount=10000,
            description=xss_payload,  # <-- Injeksi di sini
            status='completed',
            processed_at=timezone.now()
        )
        
        # 3. Login sebagai nasabah dan buka halaman riwayat mutasi
        self.client.login(username='nasabah_bion', password='password123')
        response = self.client.get(reverse('mutasi'))
        
        # 4. ASSERTION: Cek hasil render HTML-nya.
        # Sistem template Django harus melakukan auto-escaping. Tag < diubah jadi &lt; dan > jadi &gt;
        # Sehingga browser hanya menampilkan string teks biasa, BUKAN mengeksekusinya sebagai Javascript.
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")
        
        # Pastikan tag asli yang berbahaya sudah tidak ada di dalam halaman.
        self.assertNotContains(response, xss_payload)

    def test_xss_prevention_on_search_query(self):
        """Memastikan Reflected XSS dicegah pada fitur pencarian rekening"""
        self.client.login(username='nasabah_bion', password='password123')
        
        # 1. Siapkan payload XSS
        xss_payload = "<script>alert('XSS')</script>"
        
        # 2. Kirim payload sebagai parameter 'query' di URL pencarian
        response = self.client.get(reverse('search_account'), {'query': xss_payload})
        
        # 3. ASSERTION: Pastikan input yang dipantulkan (reflected) ke layar sudah ter-escape dengan aman
        self.assertContains(response, "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;")
        
        # Pastikan tidak ada tag script mentah yang lolos
        self.assertNotContains(response, xss_payload)

class CSRFMiddlewareTests(TestCase):

    # 3. CSRF PROTECTION

    """TC-CSRF-01 & 02: Memastikan Middleware CSRF aktif dan token diverifikasi"""
    def setUp(self):
        self.nasabah = User.objects.create_user(username='nasabah_csrf', password='TestPass@123', role='nasabah')
        Account.objects.create(user=self.nasabah, account_number='88889999', balance=100000)

    def test_CSRF_01a_csrf_middleware_in_settings(self):
        """CsrfViewMiddleware harus terdaftar di MIDDLEWARE settings"""
        from django.conf import settings
        self.assertIn('django.middleware.csrf.CsrfViewMiddleware', settings.MIDDLEWARE)

    def test_CSRF_02a_transfer_without_token_returns_403(self):
        """POST transfer uang tanpa CSRF token harus ditolak dengan status 403"""
        # Gunakan client khusus dengan enforce_csrf_checks=True
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.login(username='nasabah_csrf', password='TestPass@123')
        
        response = csrf_client.post(reverse('transfer'), {
            'to_account_number': '11112222',
            'amount': '10000',
            'description': 'CSRF Attack',
        })
        # Harus Forbidden karena tidak ada csrfmiddlewaretoken di payload POST
        self.assertEqual(response.status_code, 403)

class CSRFTransferTests(TestCase):
    """TC-CSRF-03: Simulasi serangan CSRF pada endpoint kritikal"""
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.nasabah = User.objects.create_user(username='nasabah_csrf_tx', password='TestPass@123', role='nasabah')
        Account.objects.create(user=self.nasabah, account_number='77776666', balance=500000)
        self.client.login(username='nasabah_csrf_tx', password='TestPass@123')

    def test_CSRF_03a_no_transaction_created_on_csrf_attack(self):
        """Pastikan saldo tidak terpotong dan transaksi tidak dibuat saat CSRF Attack"""
        initial_balance = self.nasabah.account.balance
        
        # Kirim request jahat tanpa token
        self.client.post(reverse('transfer'), {
            'to_account_number': '11112222',
            'amount': '500000',
        })
        
        # Cek Database: Tidak boleh ada transaksi yang masuk
        self.assertEqual(Transaction.objects.count(), 0)
        
        # Cek Saldo: Tidak boleh berkurang
        self.nasabah.account.refresh_from_db()
        self.assertEqual(self.nasabah.account.balance, initial_balance)

class SQLiFormTests(TestCase):

    # 4. SQL INJECTION PREVENTION

    """TC-SQLi-01 & 02: Memastikan form menolak payload SQLi dasar"""
    def test_SQLi_01a_login_injection_in_username(self):
        """LoginForm harus menolak username yang berisi bypass boolean SQL"""
        from core.forms import LoginForm
        form = LoginForm(data={
            'username': "' OR '1'='1' --",
            'password': 'anything',
        })
        # Sistem akan menganggap form tidak valid
        self.assertFalse(form.is_valid())

    def test_SQLi_02a_union_in_search_rejected(self):
        """Fitur pencarian harus kebal dari serangan UNION SELECT"""
        from core.forms import AccountSearchForm
        form = AccountSearchForm(data={
            'query': "' UNION SELECT username, password FROM core_user --",
        })
        self.assertFalse(form.is_valid())

class SQLiViewTests(TestCase):
    """TC-SQLi-03: Memastikan ORM memparameterisasi input jahat"""
    def setUp(self):
        self.client = Client()
        self.nasabah = User.objects.create_user(username='nasabah_sqli', password='TestPass@123', role='nasabah')
        self.client.login(username='nasabah_sqli', password='TestPass@123')

    def test_SQLi_03a_search_with_injection_payload_does_not_leak_data(self):
        """Search menggunakan ORM tidak mengeksekusi payload SQL"""
        # Kirim payload SQLi ke endpoint pencarian
        response = self.client.get(reverse('search_account'), {
            'query': "' UNION SELECT username, password FROM core_user --",
        })
        
        # Aplikasi tidak boleh crash (HTTP 200 OK)
        self.assertEqual(response.status_code, 200)
        
        # Pastikan hash password atau data sensitif tidak bocor di HTML
        content = response.content.decode()
        self.assertNotIn('pbkdf2_sha256', content)