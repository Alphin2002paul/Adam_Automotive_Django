# Generated by Django 5.0.6 on 2024-08-08 06:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0007_usercardetails'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='status',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
