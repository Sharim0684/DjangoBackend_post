from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from cryptography.fernet import Fernet
import os

# Generate and store encryption key
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher = Fernet(ENCRYPTION_KEY)

class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    gender = models.CharField(max_length=10)
    
    # Add this new field
    social_provider = models.CharField(max_length=20, null=True, blank=True)
    encrypted_password = models.BinaryField()

    def set_encrypted_password(self, raw_password):
        self.encrypted_password = cipher.encrypt(raw_password.encode())

    def check_encrypted_password(self, raw_password):
        return cipher.decrypt(self.encrypted_password).decode() == raw_password
