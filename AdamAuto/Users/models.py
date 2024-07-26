from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ('customer', 'Customer'),
        ('dealer', 'Dealer'),
        ('admin', 'Admin'),
    )
    
    user_type = models.CharField(max_length=50, choices=USER_TYPE_CHOICES)
    Phone_number=models.CharField(max_length=15,null=True)

    def __str__(self):
        return self.username
