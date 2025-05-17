from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid
from django.db import migrations, models
from django.utils import timezone

class User(AbstractUser):
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    gender = models.CharField(max_length=10, blank=True)
    social_provider = models.CharField(max_length=50, blank=True, null=True)
    social_id = models.CharField(max_length=255, blank=True)
    access_token = models.TextField(blank=True)
    refresh_token = models.TextField(blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'name']

    # Add related_name to fix the clash
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='api_user_set',
        blank=True,
        help_text='The groups this user belongs to.'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='api_user_set',
        blank=True,
        help_text='Specific permissions for this user.'
    )

    def __str__(self):
        return self.email


class Person(models.Model):
    name = models.CharField(max_length=100)
    age = models.IntegerField()
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.name

    # Add these new fields
    social_provider = models.CharField(max_length=20, null=True)  # facebook, linkedin, instagram, twitter
    social_id = models.CharField(max_length=255, null=True)
    social_token = models.TextField(null=True)
    social_refresh_token = models.TextField(null=True)
    social_token_expires = models.DateTimeField(null=True)


class SocialMediaCredentials(models.Model):
    PLATFORM_CHOICES = [
        ('facebook', 'Facebook'),
        ('linkedin', 'LinkedIn'),
        ('instagram', 'Instagram'),
        ('twitter', 'Twitter')
    ]

    username = models.CharField(max_length=255)
    password = models.CharField(max_length=1024)
    platform_name = models.CharField(max_length=50, choices=PLATFORM_CHOICES)
    platform_logo = models.URLField(blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='social_credentials')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['user', 'platform_name']
        db_table = 'social_media_credentials'

    def __str__(self):
        return f"{self.user.email} - {self.platform_name}"

    def save(self, *args, **kwargs):
        if not self.username:
            # Generate a unique username if not provided
            base_username = self.email.split('@')[0]
            username = base_username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}_{counter}"
                counter += 1
            self.username = username
        super().save(*args, **kwargs)


class SelectedPlatform(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    platform = models.CharField(max_length=20)  # facebook, linkedin, instagram, twitter
    is_selected = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'platform')


class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    media = models.FileField(upload_to='post_media/', null=True, blank=True)
    platforms = models.ManyToManyField(SelectedPlatform)
    scheduled_time = models.DateTimeField(null=True, blank=True)
    is_published = models.BooleanField(default=False)
    enable_likes = models.BooleanField(default=True)
    enable_comments = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Credential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    platform_name = models.CharField(max_length=50)
    access_token = models.TextField()
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'platform_name')
        db_table = 'credentials'

    def __str__(self):
        return f"{self.user.username}'s {self.platform_name} credential"












