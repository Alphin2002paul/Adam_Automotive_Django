# Generated by Django 5.0.6 on 2024-09-23 03:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0036_delete_carpurchase'),
    ]

    operations = [
        migrations.AddField(
            model_name='feedback',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
    ]
