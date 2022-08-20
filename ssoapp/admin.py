from django.contrib import messages
from django.contrib.gis import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.contrib.admin import register, ModelAdmin
from ssoapp import models

#@admin.register(models.EmailOTP)
class EmailOTP(admin.TabularInline):
    model = models.EmailOTP
    extra = 0

@admin.register(models.EmailUser)
class EmailAdmin(ModelAdmin):
    list_display = ('id', 'first_name','last_name','is_staff','is_superuser',)
    list_filter = ('is_staff','is_superuser',)
    search_fields = ('first_name','last_name','id',)
    inlines = [EmailOTP]

@admin.register(models.EmailPin)
class EmailPin(ModelAdmin):
     list_display = ('id', 'email','verify_key','pin_code','expiry','status','created')
     readonly_fields=('verify_key','pin_code')

@admin.register(models.DomainGroup)
class DomainGroupAdmin(ModelAdmin):
     list_display = ('id','domain','created')

@admin.register(models.AuthRedirect)
class AuthRedirectAdmin(ModelAdmin):
      list_display = ('id','domain_group','redirect_token','expiry','created')

