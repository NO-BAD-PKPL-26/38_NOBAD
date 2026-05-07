from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from .models import User
import re


# ── Validators ────────────────────────────────────────────────────────────────

def validate_no_injection(value):
    """
    SECURE CODING — Code Injection Prevention (CWE-79, CWE-94)
    Blocks XSS, HTML injection, SSTI (TC-CI-01, TC-CI-02, TC-CI-03).
    Uses allowlist approach: reject any dangerous pattern.
    """
    dangerous_patterns = [
        r'<script',         # TC-CI-01: XSS script tag
        r'</script>',
        r'javascript:',     # TC-CI-01: JS protocol
        r'on\w+\s*=',       # TC-CI-02: event handlers (onclick, onerror, etc)
        r'<iframe',         # HTML injection
        r'<object',
        r'<embed',
        r'<img[^>]+onerror', # TC-CI-02: img onerror
        r'vbscript:',
        r'data:text/html',
        r'\{\{',            # TC-CI-03: SSTI {{ }}
        r'\}\}',
        r'\{%',             # TC-CI-03: Django template tags
        r'%\}',
        r'<[a-zA-Z]+[^>]*>',  # any HTML tag
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, str(value), re.IGNORECASE):
            raise ValidationError(
                "Input mengandung karakter atau pola yang tidak diizinkan."
            )
    return value


def validate_amount(value):
    if value <= 0:
        raise ValidationError("Jumlah harus lebih dari 0.")
    if value > 500_000_000:
        raise ValidationError("Jumlah melebihi batas maksimum (Rp 500.000.000).")
    return value


def validate_account_number(value):
    """Allowlist: digits only, 10-16 chars (TC-SQLi-04c)"""
    if not re.match(r'^\d{10,16}$', str(value)):
        raise ValidationError("Nomor rekening tidak valid. Harus berupa angka (10-16 digit).")
    return value


# ── Forms ─────────────────────────────────────────────────────────────────────

class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Masukkan username',
            'autocomplete': 'username',
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': 'Masukkan password',
            'autocomplete': 'current-password',
        })
    )

    def clean_username(self):
        username = self.cleaned_data.get('username', '')
        # Allowlist: only safe chars
        if not re.match(r'^[\w.@+-]+$', username):
            raise ValidationError("Username mengandung karakter yang tidak valid.")
        return username


class RegisterForm(UserCreationForm):
    first_name = forms.CharField(
        max_length=50,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Nama depan'}),
        validators=[validate_no_injection]
    )
    last_name = forms.CharField(
        max_length=50,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Nama belakang'}),
        validators=[validate_no_injection]
    )
    phone = forms.CharField(
        max_length=15,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': '08xxxxxxxxxx'})
    )

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'phone', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Username unik'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in ['password1', 'password2']:
            self.fields[field].widget.attrs.update({'class': 'form-input'})

    def clean_phone(self):
        phone = self.cleaned_data.get('phone', '')
        if not re.match(r'^\+?[0-9]{8,15}$', phone):
            raise ValidationError("Nomor telepon hanya boleh berisi angka (8-15 digit).")
        return phone

    def clean_first_name(self):
        name = self.cleaned_data.get('first_name', '')
        if not re.match(r"^[a-zA-Z\s\-'\.]+$", name):
            raise ValidationError("Nama hanya boleh berisi huruf dan spasi.")
        return validate_no_injection(name)

    def clean_last_name(self):
        name = self.cleaned_data.get('last_name', '')
        if not re.match(r"^[a-zA-Z\s\-'\.]+$", name):
            raise ValidationError("Nama hanya boleh berisi huruf dan spasi.")
        return validate_no_injection(name)

class AccountSearchForm(forms.Form):
    # FORM PENCARIAN REKENING — SQL Injection Prevention (TC-SQLi-02)
    # Setiap field input divalidasi sebelum masuk ke ORM query di search_account_view()
    query = forms.CharField(
        max_length=100,  # Limit panjang input untuk performa & keamanan
        required=False,  # Optional — user boleh tidak search
        label='Cari rekening',  # Label di form
        widget=forms.TextInput(attrs={
            'class': 'form-input',  # CSS class untuk styling
            'placeholder': 'Cari nama nasabah atau nomor rekening...',  # Hint text
        }),
        # validate_no_injection() blok XSS & SSTI patterns
        # Blok patterns: <script, javascript:, onclick=, {{}}, {%...%}, dll (CWE-79, CWE-94)
        validators=[validate_no_injection]  # Custom validator di forms.py (line 6-25)
    )

class TopUpForm(forms.Form):
    account_number = forms.CharField(
        max_length=16,
        label='Nomor Rekening Nasabah',
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Nomor rekening nasabah',
        }),
        validators=[validate_account_number]
    )
    amount = forms.DecimalField(
        max_digits=15,
        decimal_places=2,
        label='Jumlah Top Up (Rp)',
        widget=forms.NumberInput(attrs={
            'class': 'form-input',
            'min': '1',
            'placeholder': '0',
        }),
        validators=[validate_amount]
    )