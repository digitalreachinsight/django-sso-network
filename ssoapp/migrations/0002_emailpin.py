# Generated by Django 3.2.12 on 2022-03-17 03:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ssoapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailPin',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('verify_key', models.CharField(max_length=1024, unique=True)),
                ('email', models.EmailField(max_length=255)),
                ('pin_code', models.CharField(max_length=255)),
                ('expiry', models.DateTimeField(blank=True, null=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
