# Generated by Django 3.2.12 on 2022-08-22 15:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ssoapp', '0011_rename_enabled_allowed_users_domaingroup_enable_allowed_users'),
    ]

    operations = [
        migrations.AddField(
            model_name='domaingroup',
            name='lookup_order',
            field=models.IntegerField(default=100),
        ),
    ]
