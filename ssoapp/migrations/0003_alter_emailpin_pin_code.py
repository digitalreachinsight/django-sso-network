# Generated by Django 3.2.12 on 2022-03-17 05:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ssoapp', '0002_emailpin'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailpin',
            name='pin_code',
            field=models.CharField(max_length=2048),
        ),
    ]