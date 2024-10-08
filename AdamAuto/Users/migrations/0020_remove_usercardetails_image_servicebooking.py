# Generated by Django 5.0.6 on 2024-08-21 08:31

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0019_carimage'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='usercardetails',
            name='image',
        ),
        migrations.CreateModel(
            name='ServiceBooking',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('service_description', models.TextField()),
                ('manufacturer_name', models.CharField(max_length=100)),
                ('model_name', models.CharField(max_length=100)),
                ('year', models.IntegerField()),
                ('transmission_type', models.CharField(choices=[('Manual', 'Manual'), ('Automatic', 'Automatic')], max_length=10)),
                ('fuel_type', models.CharField(choices=[('Petrol', 'Petrol'), ('Diesel', 'Diesel'), ('Electric', 'Electric'), ('Hybrid', 'Hybrid')], max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
