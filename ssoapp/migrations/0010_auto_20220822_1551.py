# Generated by Django 3.2.12 on 2022-08-22 15:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ssoapp', '0009_authlog'),
    ]

    operations = [
        migrations.AddField(
            model_name='domaingroup',
            name='allowed_users',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='domaingroup',
            name='enabled_allowed_users',
            field=models.BooleanField(default=False),
        ),
    ]