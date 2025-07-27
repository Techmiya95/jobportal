from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    father_name = models.CharField(max_length=255, blank=True, null=True)
    ug_college = models.CharField(max_length=255, blank=True, null=True)
    branch = models.CharField(max_length=100, blank=True, null=True)
    passout_year = models.IntegerField(blank=True, null=True)
    phone_number = models.CharField(max_length=20)

    def __str__(self):
        return self.user.username
