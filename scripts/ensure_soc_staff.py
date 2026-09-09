import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

username = 'soc-staff'
password = 'pass'
email = 'soc-staff@example.local'

user, created = User.objects.get_or_create(username=username, defaults={'email': email})
if created:
    user.set_password(password)
    user.is_staff = True
    user.is_superuser = False
    user.save()
    print(f'Created staff user {username}')
else:
    changed = False
    if not user.check_password(password):
        user.set_password(password)
        changed = True
    if not user.is_staff:
        user.is_staff = True
        changed = True
    if changed:
        user.save()
        print(f'Updated staff user {username}')
    else:
        print(f'Staff user {username} already present')
