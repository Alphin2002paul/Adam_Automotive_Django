from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ('customer', 'Customer'),
        ('dealer', 'Dealer'),
        ('admin', 'Admin'),
    )
    user_type = models.CharField(max_length=50, choices=USER_TYPE_CHOICES)
    Phone_number = models.CharField(max_length=15, null=True)
    address = models.CharField(max_length=255, null=True)
    city = models.CharField(max_length=50, blank=True)
    state = models.CharField(max_length=50, blank=True)
    zipcode = models.CharField(max_length=10, blank=True)
    status = models.CharField(max_length=255, null=True,default=1)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    description = models.TextField(null=True)


    def __str__(self):
        return self.username

class Tbl_Company(models.Model):
    company_name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.company_name

class Tbl_Color(models.Model):
    color_name = models.CharField(max_length=20, default='Unknown Color')

    def __str__(self):
        return self.color_name

class Tbl_Model(models.Model):
    model_name = models.CharField(max_length=20)

    def __str__(self):
        return self.model_name
class VehicleType(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name
    
class UserCarDetails(models.Model):
    manufacturer = models.ForeignKey(Tbl_Company, on_delete=models.CASCADE)
    model_name = models.ForeignKey(Tbl_Model, on_delete=models.CASCADE)
    year = models.IntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    color = models.ForeignKey(Tbl_Color, on_delete=models.CASCADE)
    fuel_type = models.CharField(max_length=100)
    kilometers = models.IntegerField()
    transmission = models.CharField(max_length=100)
    condition = models.CharField(max_length=100)
    reg_number = models.CharField(max_length=100)
    insurance_validity = models.DateField()
    pollution_validity = models.DateField()
    tax_validity = models.DateField()
    car_type = models.ForeignKey(VehicleType, on_delete=models.CASCADE)
    owner_status = models.CharField(max_length=100)
    car_status = models.CharField(max_length=100)
    car_cc = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.manufacturer} {self.model_name} ({self.year})"

from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class LikedCar(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='liked_cars')
    car = models.ForeignKey('UserCarDetails', on_delete=models.CASCADE, related_name='liked_by')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'car')

class CarImage(models.Model):
    car = models.ForeignKey(UserCarDetails, related_name='images', on_delete=models.CASCADE)
    image = models.ImageField(upload_to='car_images/')

    def __str__(self):
        return f"Image for {self.car}"