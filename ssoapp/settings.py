"""
Django settings for ssoapp project.

Generated by 'django-admin startproject' using Django 3.0.5.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
from confy import env, database

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY','NoRandomKeySet')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env('DEBUG',False) 
DEFAULT_FROM_EMAIL=env('DEFAULT_FROM_EMAIL','no-reply@example.com')
DEFAULT_URL = env('DEFAULT_URL','https://localhost')
ALLOWED_HOSTS = env('ALLOWED_HOSTS',[])

SESSION_COOKIE_NAME = 'sso_network_auth_session_id'
REDIRECT_COOKIE_NAME = 'sso_network_redirect_id'
# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'ssoapp',
    'crispy_forms',
    'django_crispy_jcaptcha'

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
]

ROOT_URLCONF = 'ssoapp.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'ssoapp.context_processors.template_variables',
            ],
        },
    },
]
#TEMPLATES[0]['OPTIONS']['context_processors'].append('parkstay.context_processors.parkstay_url')

WSGI_APPLICATION = 'ssoapp.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

# Database
DATABASES = {
     # Defined in the DATABASE_URL env variable.
     'default': database.config(),
}


#DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.sqlite3',
#        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
#    }
#}

# Authentication settings
LOGIN_URL = '/'
AUTHENTICATION_BACKENDS = (
                'django.contrib.auth.backends.ModelBackend',
                )
AUTH_USER_MODEL = 'ssoapp.EmailUser'
USER_FIELDS = ['email']

# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

JCAPTCHA_IMAGE_LIST = 'jcaptcha2'
JCAPTCHA_MATCHES_CLASS='ssoapp-jcaptcha-matches'

FERNET_KEY = env('FERNET_KEY',None)
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/
VERSION_NO = "1.0.1"
STATIC_URL = '/static/'

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEDIA_DIR = os.path.join(BASE_DIR, 'media')
LOG_DIR = os.path.join(BASE_DIR, 'logs')

# MEDIA
MEDIA_ROOT = MEDIA_DIR
MEDIA_URL = '/media/'
