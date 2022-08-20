"""ssoapp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,re_path, include
from ssoapp import views
from django.contrib.auth import logout, login
from django_crispy_jcaptcha import urls as jcaptchaurls
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('',views.HomePage.as_view(), name='home'),
    re_path(r'^verify/email-pin/(?P<verify_key>[\w\-_]+)/', views.VerifyEmailPIN.as_view(), name='verify-email-pin'),
    path('sign-in/email-pin/', views.EmailPinSignIn.as_view(), name='sign-in-email-pin'),
    path('sign-in/otp/', views.OTPSignIn.as_view(), name='sign-in-otp'),
    path('login-success/', views.LoginSuccess.as_view(), name='login-succes'),
    path('admin/', admin.site.urls),
    path('login/', login, name='login'),
    #path('login/', login, name='login', kwargs={'template_name': 'login.html'}),
    #path('logout/', logout, name='logout'),
    path('accounts/', include('django.contrib.auth.urls')), # new
    path('auth/logout/', views.sso_logout, name='authsso_logout'),
    path('auth/', views.Auth, name='auth'),
    path('auth_redirect/', views.AuthRedirect, name='auth_redirect'),
    path('check-auth/', views.Auth, name='check-auth'),
    path('logout/', views.sso_logout, name='sso_logout'),
    path('', include(jcaptchaurls))
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# test
