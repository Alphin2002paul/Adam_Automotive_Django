# Generated by Django 5.0.6 on 2024-08-12 11:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0013_delete_carimage'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='status',
            field=models.CharField(default=1, max_length=255, null=True),
        ),
    ]
