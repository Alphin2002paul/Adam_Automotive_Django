# Generated by Django 5.0.6 on 2024-08-06 17:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Users', '0005_remove_tbl_color_company_id_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='VehicleType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
            ],
        ),
    ]
