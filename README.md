# Tugas 3 — Secure Coding Implementation

> **Tugas 3 — Secure Coding Implementation**  
> Pengantar Keamanan Perangkat Lunak | Genap 2025/2026  
> Kelompok NOBAD

---

## 1. Deskripsi Aplikasi

### Skenario

**BankApp Secure** adalah aplikasi web simulasi **Mobile Banking Application** yang dibangun sebagai bagian dari Tugas 3 mata kuliah Pengantar Keamanan Perangkat Lunak. Aplikasi ini mensimulasikan sistem perbankan digital sederhana, di mana seluruh saldo dan transaksi disimpan di database SQLite lokal sebagai angka simulasi.

Fokus utama aplikasi adalah **implementasi secure coding** untuk melindungi dari 4 jenis serangan: Code Injection, Broken Authentication, CSRF, dan SQL Injection.

### Fitur yang Diimplementasikan

| Fitur                | Deskripsi                                                | Role       |
| -------------------- | -------------------------------------------------------- | ---------- |
| Login & Register     | Autentikasi aman dengan PBKDF2 hashing dan rate limiting | Semua      |
| Transfer Dana        | Kirim uang ke rekening lain dengan validasi input ketat  | Nasabah    |
| Mutasi Rekening      | Riwayat lengkap transaksi masuk dan keluar               | Nasabah    |
| Cari Rekening        | Pencarian nasabah/nomor rekening via ORM                 | Nasabah    |
| Top-Up               | Isi saldo rekening nasabah                               | Teller     |
| Dashboard Supervisor | Monitor semua transaksi, kelola rekening, security log   | Supervisor |

### Role Pengguna

| Role                | Deskripsi                           | Akses                                                  |
| ------------------- | ----------------------------------- | ------------------------------------------------------ |
| **Nasabah**         | Pengguna eksternal (pelanggan bank) | Transfer, mutasi, cari rekening                        |
| **Teller**          | Staf internal bank                  | Top-up rekening nasabah                                |
| **Supervisor Bank** | Admin internal                      | Monitor transaksi, kelola rekening, lihat security log |

### Stack Teknologi

| Komponen         | Teknologi                                 |
| ---------------- | ----------------------------------------- |
| Backend          | Python 3 + Django 5.x                     |
| Database         | SQLite3                                   |
| Frontend         | HTML5 + CSS3                              |
| Password Hashing | Django PBKDF2-SHA256                      |
| Session          | Django Session Framework                  |
| CSRF             | Django CSRF Middleware                    |
| ORM              | Django ORM                                |

---

## 2. Implementasi Secure Coding

---

### 2.1 Code Injection Prevention

#### Vulnerability yang Dimitigasi

| CWE    | Nama                       | Deskripsi                                                             |
| ------ | -------------------------- | --------------------------------------------------------------------- |
| CWE-79 | Cross-site Scripting (XSS) | Input pengguna dirender sebagai HTML/JavaScript oleh browser          |
| CWE-94 | Code Injection / SSTI      | Input dieksekusi sebagai kode server (Server-Side Template Injection) |
| CWE-20 | Improper Input Validation  | Tidak ada validasi format input dari pengguna                         |

**CWE-79 (XSS):** Terjadi ketika input pengguna seperti `<script>alert('XSS')</script>` disimpan ke database dan kemudian dirender oleh browser sebagai HTML aktif, bukan sebagai teks biasa.

**CWE-94 (SSTI):** Pada framework Django/Jinja2, input seperti `{{7*7}}` atau `{{config.SECRET_KEY}}` dapat dieksekusi oleh template engine, menyebabkan bocornya informasi server atau eksekusi kode berbahaya.

#### Kode Sebelum (Vulnerable)

```python
#  VULNERABLE — core/views.py
# Tidak ada validasi sama sekali, input langsung disimpan ke database
def transfer_view(request):
    if request.method == 'POST':
        description = request.POST.get('description')  # langsung ambil tanpa validasi
        to_account_number = request.POST.get('to_account_number')

        # Input berbahaya langsung masuk database:
        # description = "<script>alert('XSS')</script>"
        # description = "{{config.SECRET_KEY}}"  → bocor SECRET_KEY!
        Transaction.objects.create(description=description)
```

```html
<!--  VULNERABLE — template -->
<!-- Menggunakan |safe filter → XSS bisa dieksekusi -->
<td>{{ t.description|safe }}</td>
```

#### Kode Sesudah (Secure)

```python
#  SECURE — core/forms.py
import re
from django.core.exceptions import ValidationError

def validate_no_injection(value):
    """
    Allowlist validation — menolak semua pola berbahaya.
    TC-CI-01: XSS script tag
    TC-CI-02: HTML injection (img onerror)
    TC-CI-03: SSTI Django template injection
    TC-CI-04c: Script di field keterangan transfer
    """
    dangerous_patterns = [
        r'<script',              # TC-CI-01: XSS script tag
        r'javascript:',          # TC-CI-01: JS protocol
        r'on\w+\s*=',           # TC-CI-02: event handlers (onclick, onerror, dll)
        r'<img[^>]+onerror',    # TC-CI-02: img onerror injection
        r'<[a-zA-Z]+[^>]*>',   # HTML tag injection
        r'\{\{',                 # TC-CI-03: SSTI opening {{
        r'\}\}',                 # TC-CI-03: SSTI closing }}
        r'\{%',                  # TC-CI-03: Django template tag
        r'%\}',                  # TC-CI-03: Django template tag closing
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, str(value), re.IGNORECASE):
            raise ValidationError(
                "Input mengandung karakter atau pola yang tidak diizinkan."
            )
    return value

class TransferForm(forms.Form):
    description = forms.CharField(
        max_length=200,
        required=False,
        validators=[validate_no_injection]  # validator dipanggil otomatis
    )
    to_account_number = forms.CharField(
        validators=[validate_account_number]  # allowlist: digit 10-16 saja
    )
```

```html
<!--  SECURE — template -->
<!-- Django auto-escape aktif: {{ variable }} di-escape otomatis -->
<!-- <script> menjadi &lt;script&gt; — tidak dieksekusi browser -->
<td>{{ t.description|truncatechars:30 }}</td>
```

#### Teknik Mitigasi

1. **Allowlist Regex Validation** : fungsi `validate_no_injection()` menolak input yang mengandung pola berbahaya menggunakan regex. Pendekatan ini lebih aman daripada blacklist karena mendefinisikan apa yang _boleh_ ada, bukan yang _tidak boleh_.

2. **Django Template Auto-Escaping** : semua variabel yang dirender dengan `{{ variable }}` secara otomatis di-escape oleh Django. Karakter `<`, `>`, `"`, `'`, `&` dikonversi ke HTML entities sehingga tidak bisa dieksekusi sebagai kode.

3. **Input Validation di Form Layer** : validasi dilakukan di `forms.py` sebelum data masuk ke view atau database, memastikan data berbahaya tidak pernah tersimpan.

---

### 2.2 Broken Authentication

#### Vulnerability yang Dimitigasi

| CWE | Vulnerability | Mitigasi pada Sistem |
|---|---|---|
| CWE-256 | Plaintext Storage of Password | Password disimpan menggunakan hashing PBKDF2-SHA256 bawaan Django, bukan plaintext |
| CWE-916 | Weak Password Hash | Sistem tidak menggunakan hashing lemah seperti MD5 atau SHA1 |
| CWE-307 | Brute Force | Login hanya dapat dilakukan melalui autentikasi Django, namun belum terdapat rate limiting otomatis |
| CWE-287 | Improper Authentication | Akses halaman tertentu dibatasi menggunakan session authentication dan `@login_required` |
| CWE-613 | Insufficient Session Expiration | Session pengguna dihapus setelah logout menggunakan Django session framework |
| CWE-272 | Least Privilege Violation | Hak akses dibatasi berdasarkan role pengguna |
| CWE-204 | Observable Response Discrepancy | Pesan error login dibuat konsisten agar tidak membocorkan username valid |

#### Kode Sebelum (Vulnerable)

```python
#  VULNERABLE — autentikasi lemah

# 1. Password disimpan plaintext (CWE-256)
user.password = request.POST.get('password')  # "Nasabah@123" tersimpan apa adanya
user.save()

# 2. Tidak ada rate limiting (CWE-307)
def login_view(request):
    user = User.objects.get(username=username)
    if user.password == password:  # bisa brute-force ribuan kali!
        login(request, user)

# 3. Error message berbeda (CWE-204)
if not user_exists:
    messages.error(request, 'Username tidak ditemukan.')  # bocorkan info!
elif password_wrong:
    messages.error(request, 'Password salah.')  # attacker tahu username valid

# 4. Tidak ada role check (CWE-272)
def teller_dashboard(request):
    # siapapun bisa akses, termasuk nasabah!
    return render(request, 'teller/dashboard.html')
```

#### Kode Sesudah (Secure)

```python
#  SECURE

# 1. PBKDF2 hashing otomatis (TC-BA-01) — settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',  # 870.000 iterasi
]
# Password tersimpan sebagai: pbkdf2_sha256$870000$salt$hash=
# Tidak bisa di-reverse menjadi password asli

# 2. Rate limiting via middleware (TC-BA-02) — core/middleware.py
class LoginAttemptMiddleware:
    def __call__(self, request):
        if request.path == '/login/' and request.method == 'POST':
            ip = get_client_ip(request)
            cutoff = timezone.now() - timedelta(seconds=300)  # 5 menit
            recent_failures = LoginAttempt.objects.filter(
                ip_address=ip,
                success=False,
                timestamp__gte=cutoff
            ).count()
            if recent_failures >= 5:  # lockout setelah 5x gagal
                return HttpResponseForbidden("Akun terkunci sementara...")
        return self.get_response(request)

# 3. Error message sama untuk semua kasus (TC-BA-05) — core/views.py
user = authenticate(request, username=username, password=password)
if user is None:
    LoginAttempt.objects.create(ip_address=ip, username=username, success=False)
    messages.error(request, 'Username atau password salah.')  # SELALU sama

# 4. Session security (TC-BA-03) — settings.py
SESSION_COOKIE_HTTPONLY = True   # cookie tidak bisa diakses JavaScript
SESSION_COOKIE_SAMESITE = 'Lax' # proteksi CSRF tambahan
SESSION_COOKIE_AGE = 3600        # expired setelah 1 jam

# 5. Least privilege dengan decorator (TC-BA-04) — core/views.py
def role_required(*roles):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            if request.user.role not in roles:
                raise PermissionDenied  # 403 Forbidden
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

@login_required
@role_required('teller')      # hanya teller yang bisa akses
def teller_dashboard(request): ...

@login_required
@role_required('supervisor')  # hanya supervisor yang bisa akses
def supervisor_dashboard(request): ...
```

#### Teknik Mitigasi

1. **PBKDF2-SHA256 Password Hashing** : Django menggunakan PBKDF2 dengan 870.000 iterasi secara default. Bahkan jika database bocor, password tidak bisa di-reverse.

2. **Rate Limiting / Lockout** : `LoginAttemptMiddleware` mencatat setiap percobaan login dan memblokir IP setelah 5x gagal dalam 5 menit, mencegah brute force attack.

3. **Generic Error Message** : pesan error login selalu "Username atau password salah" tanpa membedakan apakah username atau password yang salah, mencegah username enumeration attack.

4. **Session Management** : `SESSION_COOKIE_HTTPONLY` mencegah JavaScript mengakses cookie session. Session di-invalidate saat logout via `logout(request)`.

5. **Role-Based Access Control (Least Privilege)** : setiap view dilindungi decorator `@role_required()` yang memastikan hanya role yang berwenang dapat mengakses halaman tersebut.

---

### 2.3 CSRF Protection

#### Vulnerability yang Dimitigasi

| CWE     | Nama                       | Deskripsi                                                                          |
| ------- | -------------------------- | ---------------------------------------------------------------------------------- |
| CWE-352 | Cross-Site Request Forgery | Request berbahaya dari situs lain yang memalsukan identitas user yang sedang login |

**Skenario serangan:** Penyerang membuat halaman web jahat dengan form tersembunyi yang menarget endpoint transfer. Ketika korban (yang sedang login di BankApp) membuka halaman jahat tersebut, browser secara otomatis mengirim cookie session yang valid, sehingga server mengira request datang dari korban sendiri.

#### Kode Sebelum (Vulnerable)

```html
<!--  VULNERABLE — form tanpa CSRF token -->
<!-- Penyerang bisa buat form ini di situs lain dan trigger otomatis -->
<form method="post" action="http://bankapp.com/nasabah/transfer/">
  <input name="to_account_number" value="rekening_penyerang" />
  <input name="amount" value="9999999" />
</form>
<script>
  document.forms[0].submit();
</script>
<!-- Korban yang sedang login akan kehilangan saldo tanpa sadar! -->
```

```python
#  VULNERABLE — settings.py
MIDDLEWARE = [
    # CsrfViewMiddleware tidak ada — tidak ada verifikasi token
]
```

#### Kode Sesudah (Secure)

```python
#  SECURE — settings.py
MIDDLEWARE = [
    ...
    'django.middleware.csrf.CsrfViewMiddleware',  # verifikasi token server-side
    ...
]

# Logout hanya via POST untuk mencegah CSRF logout attack — core/views.py
def logout_view(request):
    if request.method == 'POST':  # GET request tidak bisa logout
        logout(request)
    return redirect('login')
```

```html
<!--  SECURE — setiap form POST wajib punya {% csrf_token %} -->

<!-- Form Transfer (TC-CSRF-04c) -->
<form method="post" action="{% url 'transfer' %}">
  {% csrf_token %}
  <!-- Django render: <input type="hidden" name="csrfmiddlewaretoken" value="AbCd1234..."> -->
  ...
</form>

<!-- Form Top-Up -->
<form method="post" action="{% url 'topup' %}">{% csrf_token %} ...</form>

<!-- Form Toggle Rekening (Supervisor) -->
<form method="post" action="{% url 'toggle_account' acc.id %}">
  {% csrf_token %}
  <button type="submit">Toggle</button>
</form>

<!-- Form Logout -->
<form method="post" action="{% url 'logout' %}">
  {% csrf_token %}
  <button type="submit">Logout</button>
</form>
```

#### Teknik Mitigasi

1. **CSRF Token per Request** : `{% csrf_token %}` di setiap form menghasilkan token acak unik yang terikat ke session pengguna. Situs lain tidak bisa mengetahui nilai token ini.

2. **Server-Side Verification** : `CsrfViewMiddleware` memverifikasi token di setiap request POST sebelum request diproses. Jika token tidak ada atau tidak cocok, Django otomatis mengembalikan **HTTP 403 Forbidden**.

3. **SameSite Cookie** : `SESSION_COOKIE_SAMESITE = 'Lax'` mencegah cookie dikirim dalam cross-site request, memberikan lapisan proteksi tambahan.

4. **POST-only Logout** : Logout hanya bisa dilakukan via POST request (bukan GET link), mencegah penyerang me-logout korban secara diam-diam dengan menyisipkan `<img src="/logout/">`.

---

### 2.4 SQL Injection Prevention

#### Vulnerability yang Dimitigasi

| CWE    | Nama                      | Deskripsi                                                                         |
| ------ | ------------------------- | --------------------------------------------------------------------------------- |
| CWE-89 | SQL Injection             | Input pengguna dimasukkan langsung ke query SQL, memungkinkan manipulasi database |
| CWE-20 | Improper Input Validation | Input tidak divalidasi sebelum digunakan dalam query                              |

**Skenario serangan:**

- **Login bypass:** `' OR '1'='1' --` di field username → query selalu return true → masuk tanpa password
- **Data extraction:** `' UNION SELECT username, password FROM core_user --` di search bar → bocorkan semua password hash
- **Data manipulation:** `'; DROP TABLE core_account; --` → hapus seluruh tabel rekening

#### Kode Sebelum (Vulnerable)

```python
# VULNERABLE — raw SQL dengan string concatenation

# Login bypass (TC-SQLi-01)
def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    # Input: username = "' OR '1'='1' --"
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # Query jadi: WHERE username='' OR '1'='1' --' AND password='...'
    # Hasilnya: login BERHASIL tanpa password yang benar!
    cursor.execute(query)

# UNION injection via search (TC-SQLi-02)
def search_view(request):
    q = request.GET.get('q')
    # Input: "' UNION SELECT username, password, null FROM core_user --"
    query = "SELECT * FROM core_account WHERE account_number LIKE '%" + q + "%'"
    # Hasilnya: mengembalikan semua username + password hash dari tabel user!
    cursor.execute(query)

# Transfer injection (TC-SQLi-04c)
def transfer_view(request):
    acc_num = request.POST.get('to_account_number')
    # Input: "1234567890' OR '1'='1' --"
    query = f"SELECT * FROM core_account WHERE account_number = '{acc_num}'"
    # Hasilnya: return semua rekening, transfer ke rekening yang salah!
    cursor.execute(query)
```

#### Kode Sesudah (Secure)

```python
# SECURE — Django ORM, parameterized query otomatis

# Login — Django authenticate() menggunakan ORM internally (TC-SQLi-01)
# core/views.py
user = authenticate(request, username=username, password=password)
# Django ORM generate: WHERE username = %s AND password = %s
# Parameter di-escape otomatis — injection tidak bisa

# Search dengan Q objects ORM (TC-SQLi-02)
# core/views.py — search_account_view()
from django.db.models import Q

results = Account.objects.filter(
    Q(account_number__icontains=query) |     # parameterized: LIKE %?%
    Q(user__first_name__icontains=query) |   # parameterized: LIKE %?%
    Q(user__last_name__icontains=query),
    is_active=True
).exclude(user=request.user).select_related('user')[:10]
# UNION injection tidak bisa — ORM tidak mengizinkan raw SQL dari input

# Transfer — ORM get() (TC-SQLi-04c)
# core/views.py — transfer_view()
to_account = Account.objects.get(
    account_number=to_acc_num,  # parameterized: WHERE account_number = ?
    is_active=True
)
# Input "1234567890' OR '1'='1' --" sudah ditolak di form layer sebelumnya
# Karena validate_account_number() hanya izinkan digit 10-16 karakter

# Top-up — ORM get() (topup_view)
account = Account.objects.get(
    account_number=acc_num,
    is_active=True
)

# Verifikasi tidak ada raw SQL — TC-SQLi-03
# Jalankan: grep -rn "cursor.execute" core/
# Hasilnya: (kosong) — tidak ada raw SQL di seluruh project
```

```python
# Validasi input sebagai lapisan pertama — core/forms.py

def validate_account_number(value):
    """
    Allowlist: hanya digit, 10-16 karakter.
    Input seperti "' OR '1'='1' --" langsung ditolak di sini,
    tidak pernah sampai ke ORM.
    """
    if not re.match(r'^\d{10,16}$', str(value)):
        raise ValidationError(
            "Nomor rekening tidak valid. Harus berupa angka (10-16 digit)."
        )
    return value
```

#### Teknik Mitigasi

1. **Django ORM (Parameterized Queries)** : semua operasi database menggunakan Django ORM yang secara otomatis menggunakan parameterized queries. Nilai dari input pengguna tidak pernah langsung digabungkan ke string SQL.

2. **Input Validation di Form Layer** : `validate_account_number()` menerapkan allowlist (hanya digit 10-16 karakter) sehingga input SQL injection seperti `' OR '1'='1' --` ditolak bahkan sebelum mencapai layer ORM.

3. **Zero Raw SQL** : tidak ada satupun `cursor.execute()` dengan string concatenation di seluruh codebase. Dapat diverifikasi dengan: `grep -rn "cursor.execute" core/`

4. **Least Privilege Database** : setiap role hanya mengakses data yang relevan. Nasabah hanya bisa lihat transaksi miliknya sendiri, tidak bisa akses data nasabah lain.

---

## 3. Screenshot Aplikasi

### Halaman Login

![Login Page](screenshots/app-login.png)

---

### Halaman Register

![Register Page](screenshots/app-register.png)

---

### Dashboard Nasabah

![Dashboard Nasabah](screenshots/app-dashboard-nasabah.png)

---

### Halaman Transfer Dana

![Transfer](screenshots/app-transfer.png)

---

### Halaman Mutasi Rekening

![Mutasi](screenshots/app-mutasi.png)

---

### Halaman Cari Rekening

![Cari Rekening](screenshots/app-cari-rekening.png)

---

### Dashboard Teller

![Dashboard Teller](screenshots/app-dashboard-teller.png)

---

### Halaman Top-Up

![Top-Up](screenshots/app-topup.png)

---

### Dashboard Supervisor

![Dashboard Supervisor](screenshots/app-dashboard-supervisor.png)

---

### Halaman Kelola Rekening (Supervisor)

![Kelola Rekening](screenshots/app-kelola-rekening.png)

---

### Fitur Keamanan — Halaman Lockout (TC-BA-02)

![Lockout Page](screenshots/app-lockout.png)

---

## 4. Hasil Test-Case

### TC-SQLi-01 — Login Bypass via SQL Injection

- **Input:** Username: `' OR '1'='1' --` | Password: bebas
- **Expected:** Login GAGAL, pesan "Username atau password salah."

![TC-SQLi-01_NOBAD.png](screenshots/TC-SQLi-01_NOBAD.png)

---

### TC-SQLi-02 — Data Extraction via Search Input (UNION Injection)

- **Input di Cari Rekening:** `' UNION SELECT username, password, null FROM core_user --`
- **Expected:** Error validasi "Input mengandung karakter berbahaya". Tidak ada data password bocor

![TC-SQLi-02_NOBAD.png](screenshots/TC-SQLi-02_NOBAD.png)

---

### TC-SQLi-03 — Parameterized Query Verification (White-box)

- **Metode:** Code review
- **Expected:** Tidak ditemukan raw SQL — semua pakai ORM

![TC-SQLi-03_NOBAD.png](screenshots/TC-SQLi-03_NOBAD.png)

---

### TC-SQLi-04c — Banking: Input Nomor Rekening Transfer

- **Input di field Nomor Rekening Transfer:** `1234567890' OR '1'='1' --`
- **Expected:** Error "Nomor rekening tidak valid. Harus berupa angka (10-16 digit)"

![TC-SQLi-04c_NOBAD.png](screenshots/TC-SQLi-04c_NOBAD.png)

---

### TC-CI-01 — Script Tag Injection (Stored XSS)

- **Input di field Keterangan Transfer:** `<script>alert('XSS')</script>`
- **Expected:** Error "Input mengandung karakter atau pola yang tidak diizinkan". Tidak ada popup alert

![TC-CI-01_NOBAD.png](screenshots/TC-CI-01_NOBAD.png)

---

### TC-CI-02 — HTML Injection via Input Field

- **Input di field Keterangan Transfer:** `<h1>Hacked</h1><img src=x onerror=alert(1)>`
- **Expected:** Error validasi. Tidak ada HTML yang dirender

![TC-CI-02_NOBAD.png](screenshots/TC-CI-02_NOBAD.png)

---

### TC-CI-03 — Template Injection (SSTI)

- **Input di field Keterangan Transfer:** `{{7*7}}`
- **Expected:** Error validasi, tidak tampil `49`, SECRET_KEY tidak bocor

![TC-CI-03_NOBAD.png](screenshots/TC-CI-03_NOBAD.png)

---

### TC-CI-04c — Banking: Berita/Catatan Transaksi

- **Input di field Keterangan Transfer:** `<script>alert('transfer intercepted')</script>`
- **Expected:** Error validasi. Tidak ada popup alert

![TC-CI-04c_NOBAD.png](screenshots/TC-CI-04c_NOBAD.png)

---

### TC-BA-01 — Password Hashing Verification (White-box)

- **Metode:** Django shell → `print(u.password)`
- **Expected:** Output `pbkdf2_sha256$870000$...` / hashed

![TC-BA-01_NOBAD.png](screenshots/TC-BA-01_NOBAD.png)

---

### TC-BA-02 — Brute Force / Rate Limiting

- **Langkah:** Login 6x berturut-turut dengan password salah
- **Expected:** Percobaan ke-6 mendapat halaman 403 "Akun Terkunci Sementara"

![TC-BA-02_NOBAD.png](screenshots/TC-BA-02_NOBAD.png)

---

### TC-BA-03 — Session Token Invalidation setelah Logout

- **Langkah:** Login → logout → akses `/nasabah/` langsung
- **Expected:** Redirect ke halaman login — tidak bisa akses dashboard

![TC-BA-03_NOBAD.png](screenshots/TC-BA-03_NOBAD.png)

![TC-BA-03_NOBAD_2.png](screenshots/TC-BA-03_NOBAD_2.png)

---

### TC-BA-04 — Akses Halaman Terproteksi Tanpa Login

- **URL yang diuji:**
  - `/nasabah/mutasi/` → tanpa login
- **Expected:** Redirect ke login (tanpa login) atau 403 Forbidden (cross-role)

![TC-BA-04_NOBAD.png](screenshots/TC-BA-04_NOBAD.png)

---

### TC-BA-05 — Informasi Error yang Tidak Informatif

- **Skenario 1:** Username valid (`nasabah1`) + password salah → pesan error
- **Skenario 2:** Username tidak terdaftar (`dionwisdom1`) + password sembarang → pesan error
- **Expected:** Kedua pesan **SAMA**: `"Username atau password salah."`

![TC-BA-05_NOBAD_1.png](screenshots/TC-BA-05_NOBAD_1.png)

![TC-BA-05_NOBAD_2.png](screenshots/TC-BA-05_NOBAD_2.png)

---

### TC-CSRF-01 — CSRF Token Presence on Forms

- **Metode:** Inspect Element di semua form POST
- **Expected:** Ada `<input type="hidden" name="csrfmiddlewaretoken" value="...">`
- **Form yang dicek:** Login, Register, Transfer, Top-Up, Toggle Rekening, Logout

![TC-CSRF-01_NOBAD_1.png](screenshots/TC-CSRF-01_NOBAD_1.png)

![TC-CSRF-01_NOBAD_2.png](screenshots/TC-CSRF-01_NOBAD_2.png)

![TC-CSRF-01_NOBAD_3.png](screenshots/TC-CSRF-01_NOBAD_3.png)

![TC-CSRF-01_NOBAD_4.png](screenshots/TC-CSRF-01_NOBAD_4.png)

![TC-CSRF-01_NOBAD_5.png](screenshots/TC-CSRF-01_NOBAD_5.png)

---

### TC-CSRF-02 — Request dengan CSRF Token Invalid Ditolak

- **Metode:** Firefox DevTools "Edit and Resend" — ubah `csrfmiddlewaretoken=invalid_token_12345`
- **Expected:** Server merespons HTTP 403 Forbidden

![TC-CSRF-02_NOBAD.png](screenshots/TC-CSRF-02_NOBAD.png)

![TC-CSRF-02_NOBAD_2.png](screenshots/TC-CSRF-02_NOBAD_2.png)

---

### TC-CSRF-03 — Simulasi Cross-Origin Request (Tanpa Token)

- **Metode:** Buka `csrf_attack.html` saat sedang login
- **File `csrf_attack.html`:**
  ```html
  <form id="f" method="POST" action="http://127.0.0.1:8000/nasabah/transfer/">
    <input name="to_account_number" value="9999999999" />
    <input name="amount" value="999999" />
    <input name="description" value="hacked by csrf" />
  </form>
  <script>
    document.getElementById("f").submit();
  </script>
  ```
- **Expected:** HTTP 403 CSRF verification failed — transfer tidak terjadi

![TC-CSRF-03_NOBAD.png](screenshots/TC-CSRF-03_NOBAD.png)

---

### TC-CSRF-04c — Banking: Form Transfer Dana

- **Metode:** Sama dengan TC-CSRF-03, target endpoint `/nasabah/transfer/`
  ```html
    <form id="attackForm"
        method="POST"
        action="http://127.0.0.1:8000/nasabah/transfer/">
        <input type="hidden"
            name="to_account_number"
            value="9999999999">

        <input type="hidden"
            name="amount"
            value="999999">

        <input type="hidden"
            name="description"
            value="CSRF Attack">
    </form>
    <script>
        document.getElementById("attackForm").submit();
    </script>
  ```
- **Expected:** HTTP 403 — saldo tidak berkurang

![TC-CSRF-04c_NOBAD.png](screenshots/TC-CSRF-04c_NOBAD.png)

---

## 5. Instalasi

### Langkah Instalasi

```bash
# 1a. Clone repository
git clone https://gitlab.cs.ui.ac.id/pkpl26/38-no-bad/pkpl26_38_nobad.git
cd pkpl26_38_nobad

# 1b. Alternative clone repository
git clone https://github.com/NO-BAD-PKPL-26/38_NOBAD.git
cd 38_NOBAD

# 2. Buat virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac / Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Jalankan migrasi database
python manage.py migrate

# 5. Buat akun demo
python manage.py seed_data

# 6. Jalankan server
python manage.py runserver
```

Buka di browser: **http://127.0.0.1:8000**

### Akun Demo

| Role       | Username      | Password         | Saldo Awal    |
| ---------- | ------------- | ---------------- | ------------- |
| Supervisor | `supervisor1` | `Supervisor@123` | —             |
| Teller     | `teller1`     | `Teller@123`     | —             |
| Nasabah    | `nasabah1`    | `Nasabah@123`    | Rp 5.000.000  |
| Nasabah    | `nasabah2`    | `Nasabah@123`    | Rp 10.000.000 |
| Nasabah    | `nasabah3`    | `Nasabah@123`    | Rp 2.500.000  |

---

## 6. Video Demo

> _(placeholder)_

**Link:** [YouTube — BankApp Secure Demo](https://youtu.be/4SJo829-nA4)


_Dibuat oleh Kelompok NOBAD — PKPL Genap 2025/2026_

---

# Tugas 4 — Unit Testing dan Pentesting

> **Tugas 4 — Unit Testing dan Pentesting**  
> Pengantar Keamanan Perangkat Lunak | Genap 2025/2026  
> Kelompok NOBAD

---

## Tautan Video Demo

[ [PLACEHOLDER] Tautan Video Demo Youtube (Unlisted) ]

---

## A. Laporan Unit Testing

Pengujian unit (Unit Testing) berfokus pada verifikasi ketahanan mekanisme keamanan yang diimplementasikan pada kode sumber aplikasi perbankan (BankApp). Pengujian dilakukan menggunakan modul bawaan Django `django.test.TestCase` dan objek `Client`.

### 1. Broken Authentication Mitigation (Passed)

Bagian pengujian ini memvalidasi efektivitas manajemen sesi, pembatasan hak akses minimum (_least privilege_), dan pencegahan enumerasi akun pada fitur autentikasi.

| ID Test Case | Fungsi Uji                                      | Skenario Pengujian                                                                                                                                               | Status     |
| :----------- | :---------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------- |
| **TC-BA-01** | `test_least_privilege_access`                   | Menguji apakah akun dengan peran (_role_) Nasabah diblokir secara otomatis (HTTP 403 Forbidden) saat memaksa mengakses halaman dasbor Teller.                    | **PASSED** |
| **TC-BA-02** | `test_generic_login_error_message`              | Memastikan pesan kesalahan _login_ bersifat generik baik ketika _username_ tidak terdaftar maupun ketika _password_ salah, guna mencegah _username enumeration_. | **PASSED** |
| **TC-BA-03** | `test_unauthenticated_user_redirected_to_login` | Memverifikasi bahwa pengguna yang belum terautentikasi (belum _login_) otomatis dialihkan ke halaman _login_.                                                    | **PASSED** |
| **TC-BA-04** | `test_logout_only_accepts_post`                 | Menguji ketahanan mekanisme dengan memastikan pemanggilan fungsi _logout_ melalui metode GET ditolak.                                                            | **PASSED** |

### 2. Code Injection Prevention (Passed)

Bagian pengujian ini memvalidasi kemampuan aplikasi dalam menangkal serangan _Cross-Site Scripting_ (XSS).

| ID Test Case | Fungsi Uji                                   | Skenario Pengujian                                                                                                                        | Status     |
| :----------- | :------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------- | :--------- |
| **TC-CI-01** | `test_xss_prevention_on_transaction_history` | Menginjeksikan _payload_ tag script fiktif ke kolom deskripsi. Memastikan _template layer_ melakukan _auto-escaping_ pada riwayat mutasi. | **PASSED** |
| **TC-CI-02** | `test_xss_prevention_on_search_query`        | Memasukkan _payload_ berbahaya melalui query URL pencarian dan memastikan input dipantulkan dalam bentuk ter-_escape_ secara aman.        | **PASSED** |

### 3. SQL Injection Prevention (Tugas Ojan)

| ID Test Case   | Fungsi Uji      | Skenario Pengujian     | Status        |
| :------------- | :-------------- | :--------------------- | :------------ |
| **TC-SQLi-01** | `[Placeholder]` | _[Deskripsi skenario]_ | **[PENDING]** |

### 4. CSRF Protection (Tugas Ojan)

| ID Test Case   | Fungsi Uji      | Skenario Pengujian     | Status        |
| :------------- | :-------------- | :--------------------- | :------------ |
| **TC-CSRF-01** | `[Placeholder]` | _[Deskripsi skenario]_ | **[PENDING]** |

---

## B. Laporan Pentesting

_(Bagian ini disediakan khusus untuk dokumentasi Tim Pentest: Fino, Dimaz, Natan). Laporannya disesuaikan aja sesuai kebutuhan_
