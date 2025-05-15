from django.db import models
from api.models import User, SelectedPlatform

class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    media = models.FileField(upload_to='posts/', null=True, blank=True)
    scheduled_time = models.DateTimeField(null=True, blank=True)
    enable_likes = models.BooleanField(default=True)
    enable_comments = models.BooleanField(default=True)
    is_published = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    platforms = models.ManyToManyField(SelectedPlatform)

    def __str__(self):
        return f"{self.user.name}'s post - {self.created_at}"

# Create your models here.
