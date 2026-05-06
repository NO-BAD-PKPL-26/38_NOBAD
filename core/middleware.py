from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponseForbidden


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


class LoginAttemptMiddleware:
    """
    SECURE CODING — Broken Authentication (CWE-307)
    Rate limiting: lockout after MAX_LOGIN_ATTEMPTS failures within LOGIN_LOCKOUT_DURATION seconds (Akun akan terkunci jika 5x percobaan gagal dengan durasi lock 5 menit).
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path == '/login/' and request.method == 'POST':
            from core.models import LoginAttempt
            ip = get_client_ip(request)
            max_attempts = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
            lockout_duration = getattr(settings, 'LOGIN_LOCKOUT_DURATION', 300)
            cutoff = timezone.now() - timedelta(seconds=lockout_duration)
            recent_failures = LoginAttempt.objects.filter(
                ip_address=ip, success=False, timestamp__gte=cutoff
            ).count()
            if recent_failures >= max_attempts:
                return HttpResponseForbidden(
                    "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                    "<title>Akun Terkunci</title>"
                    "<style>body{font-family:Arial,sans-serif;display:flex;align-items:center;"
                    "justify-content:center;min-height:100vh;margin:0;background:#f0f4f8;}"
                    ".box{background:white;padding:40px;border-radius:16px;text-align:center;"
                    "box-shadow:0 4px 20px rgba(0,0,0,.1);max-width:420px;}"
                    ".icon{font-size:56px;} h2{color:#ef4444;margin:16px 0 8px;}"
                    "p{color:#64748b;} a{color:#2563a8;text-decoration:none;font-weight:600;}"
                    "</style></head><body><div class='box'>"
                    "<div class='icon'>🔒</div>"
                    "<h2>Akun Terkunci Sementara</h2>"
                    "<p>Terlalu banyak percobaan login gagal.<br>"
                    "Silakan coba lagi dalam <strong>5 menit</strong>.</p>"
                    "<br><a href='/login/'>← Kembali ke Login</a>"
                    "</div></body></html>"
                )
        return self.get_response(request)
