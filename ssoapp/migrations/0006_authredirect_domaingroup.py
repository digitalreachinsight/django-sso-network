# Generated by Django 3.2.12 on 2022-03-21 04:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('ssoapp', '0005_alter_emailpin_status'),
    ]

    operations = [
        migrations.CreateModel(
            name='DomainGroup',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(max_length=1024, unique=True)),
                ('template_group', models.CharField(max_length=100)),
                ('from_address', models.CharField(default='no-reply@example.com', max_length=500)),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='AuthRedirect',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('redirect_token', models.CharField(max_length=1024, unique=True)),
                ('expiry', models.DateTimeField(blank=True, null=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('domain_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='ssoapp.domaingroup')),
            ],
        ),
    ]
