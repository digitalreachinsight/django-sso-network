"""
WSGI config for ssoapp project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/howto/deployment/wsgi/
"""

import os
import confy

from django.core.wsgi import get_wsgi_application

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
confy.read_environment_file(BASE_DIR+"/.env")
os.environ.setdefault("BASE_DIR", BASE_DIR)


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ssoapp.settings')

application = get_wsgi_application()
