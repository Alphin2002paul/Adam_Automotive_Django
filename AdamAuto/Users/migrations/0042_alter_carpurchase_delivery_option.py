# Generated by Django 5.0.6 on 2024-09-23 05:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0041_carpurchase'),
    ]

    operations = [
        migrations.AlterField(
            model_name='carpurchase',
            name='delivery_option',
            field=models.CharField(default='showroom', max_length=20),
        ),
    ]
