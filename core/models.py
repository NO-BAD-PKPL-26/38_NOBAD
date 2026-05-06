from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid, random


class User(AbstractUser):
    ROLE_CHOICES = [
        ('nasabah', 'Nasabah'),
        ('teller', 'Teller'),
        ('supervisor', 'Supervisor Bank'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='nasabah')
    phone = models.CharField(max_length=15, blank=True)

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"


class Account(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='account')
    account_number = models.CharField(max_length=16, unique=True)
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.account_number} - {self.user.get_full_name()}"


class Transaction(models.Model):
    TYPE_CHOICES = [
        ('transfer', 'Transfer'),
        ('topup', 'Top Up'),
        ('withdraw', 'Penarikan'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Selesai'),
        ('rejected', 'Ditolak'),
    ]
    transaction_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    from_account = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True, blank=True, related_name='outgoing')
    to_account = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True, blank=True, related_name='incoming')
    transaction_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    description = models.TextField(blank=True, max_length=500)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='completed')
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_transactions')

    class Meta:
        ordering = ['-created_at']


class LoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=150)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
