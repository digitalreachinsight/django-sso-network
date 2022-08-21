from __future__ import unicode_literals

import os
import zlib

from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.contrib.postgres.fields import JSONField


from django.db import models, IntegrityError, transaction
from django.utils import timezone
from django.dispatch import receiver
from django.db.models import Q
from django.db.models.signals import post_delete, pre_save, post_save
from django.core.exceptions import ValidationError

from django_countries.fields import CountryField

from datetime import datetime, date



class EmailUserManager(BaseUserManager):
    """A custom Manager for the EmailUser model.
    """
    use_in_migrations = True

    def _create_user(self, email, password, is_staff, is_superuser, **extra_fields):
        """Creates and saves an EmailUser with the given email and password.
        """
        if not email:
            raise ValueError('Email must be set')
        email = self.normalize_email(email).lower()
        if EmailUser.objects.filter(email__iexact=email):
            raise ValueError('This email is already in use')
        user = self.model(
            email=email, is_staff=is_staff, is_superuser=is_superuser)
        user.extra_data = extra_fields
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        return self._create_user(email, password, False, False, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(email, password, True, True, **extra_fields)

class EmailUser(AbstractBaseUser, PermissionsMixin):
    """Custom authentication model for the sso app.
    Password and email are required. Other fields are optional.
    """
    email = models.EmailField(unique=True, blank=False)
    first_name = models.CharField(max_length=128, blank=False, verbose_name='Given name(s)')
    last_name = models.CharField(max_length=128, blank=False)
    is_staff = models.BooleanField(
        default=False,
        help_text='Designates whether the user can log into the admin site.',
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Designates whether this user should be treated as active.'
                  'Unselect this instead of deleting ledger.accounts.',
    )
    date_joined = models.DateTimeField(default=timezone.now)

    TITLE_CHOICES = (
        ('Mr', 'Mr'),
        ('Miss', 'Miss'),
        ('Mrs', 'Mrs'),
        ('Ms', 'Ms'),
        ('Dr', 'Dr')
    )
    title = models.CharField(max_length=100, choices=TITLE_CHOICES, null=True, blank=True,
                             verbose_name='title', help_text='')

    objects = EmailUserManager()
    USERNAME_FIELD = 'email'

    def save(self, *args, **kwargs):
        if not self.email:
            self.email = self.get_dummy_email()

        self.email = self.email.lower()
        super(EmailUser, self).save(*args, **kwargs)

    def get_full_name(self):
        full_name = '{} {}'.format(self.first_name, self.last_name)
        #.encode('utf-8').strip()
        return full_name

    def get_short_name(self):
        if self.first_name:
            return self.first_name.split(' ')[0]
        return self.email


class EmailOTP(models.Model):
    STATUS = (
                ('active', 'Active'),
                ('inactive', 'Inactive')
             )


    email = models.ForeignKey(EmailUser, blank=True, null=True, on_delete=models.PROTECT)
    otp_key = models.CharField(max_length=2048, unique=True)
    status = models.CharField(max_length=100, choices=STATUS, null=True, blank=True,verbose_name='Status', help_text='', default='inactive')
    created = models.DateTimeField(auto_now_add=True,)


class EmailPin(models.Model):
    STATUS = ( 
                ('activated', 'Activated'),
                ('notactivated', 'Not Activated')
             )
    verify_key = models.CharField(max_length=1024, unique=True)
    email = models.EmailField(max_length=255)
    pin_code = models.CharField(max_length=2048, help_text='encrypted pin code' )
    expiry = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=100, choices=STATUS, null=True, blank=True,verbose_name='Status', help_text='', default='notactivated')
    created = models.DateTimeField(auto_now_add=True,)

    def __str__(self):
        return "{}".format(self.email)

class DomainGroup(models.Model):
    domain = models.CharField(max_length=1024, unique=True)
    template_group = models.CharField(max_length=100)
    from_address =  models.CharField(max_length=500, default='no-reply@example.com')
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{}".format(self.domain)

class AuthRedirect(models.Model):
    redirect_token = models.CharField(max_length=1024, unique=True)
    domain_group = models.ForeignKey(DomainGroup, blank=True, null=True, on_delete=models.PROTECT)  
    expiry = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{} {}".format(self.domain_group, self.redirect_token)


class AuthLog(models.Model):
    """ Auth Attempt Log """

    LOGIN_METHOD = (
                ('otp', 'OTP'),
                ('emailpin', 'Email PIN')
             )

    user_agent = models.CharField(max_length=255,)
    ip_address = models.GenericIPAddressField(verbose_name='IP Address',null=True,)
    email = models.CharField(max_length=255, null=True,)
    login_method = models.CharField(max_length=100, choices=LOGIN_METHOD, null=True, blank=True,verbose_name='Login Method', help_text='', default='none') 
    http_accept = models.CharField(verbose_name='HTTP Accept',max_length=1025,)
    path_info = models.CharField(verbose_name='Path', max_length=255,)
    attempt_time = models.DateTimeField(auto_now_add=True,)
    login_valid = models.BooleanField(default=False,)

    class Meta:
        ordering = ['-attempt_time']

