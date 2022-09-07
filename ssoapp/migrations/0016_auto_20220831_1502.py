# Generated by Django 3.2.12 on 2022-08-31 15:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ssoapp', '0015_domaingroup_logo'),
    ]

    operations = [
        migrations.AddField(
            model_name='authredirect',
            name='return_url',
            field=models.CharField(default='', max_length=2048),
        ),
        migrations.AlterField(
            model_name='domaingroup',
            name='logo',
            field=models.FileField(null=True, upload_to='domaingroup/%Y/%m/%d'),
        ),
    ]