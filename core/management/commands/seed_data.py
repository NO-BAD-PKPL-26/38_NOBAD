from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from core.models import User, Account
import random

class Command(BaseCommand):
    help = 'Seed demo users'

    def handle(self, *args, **options):
        data = [
            ('supervisor1','Budi','Santoso','supervisor','Supervisor@123',True,0),
            ('teller1','Siti','Rahayu','teller','Teller@123',False,0),
            ('nasabah1','Andi','Wijaya','nasabah','Nasabah@123',False,5000000),
            ('nasabah2','Dewi','Kusuma','nasabah','Nasabah@123',False,10000000),
            ('nasabah3','Rudi','Hartono','nasabah','Nasabah@123',False,2500000),
        ]
        for username, first, last, role, pwd, is_staff, balance in data:
            if not User.objects.filter(username=username).exists():
                u = User.objects.create(
                    username=username, first_name=first, last_name=last,
                    role=role, password=make_password(pwd), is_staff=is_staff,
                )
                if role == 'nasabah':
                    acc_num = str(random.randint(1000000000, 9999999999))
                    Account.objects.create(user=u, account_number=acc_num, balance=balance)
                    self.stdout.write(f'  {role}: {username} / {pwd} | Rek: {acc_num} | Saldo: Rp {balance:,}')
                else:
                    self.stdout.write(f'  {role}: {username} / {pwd}')
        self.stdout.write(self.style.SUCCESS('\n✅ Seed selesai!'))
