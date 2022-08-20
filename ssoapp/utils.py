from ssoapp import models
from ssoapp import emails
from cryptography.fernet import Fernet
from django.conf import settings
import string
import random
import datetime
import secrets

def generate_pin(size=6, chars=string.digits):
    return ''.join(random.choice(chars) for x in range(size))

def generate_key():
    # help with generating a new key in a new environment.
    key = Fernet.generate_key()
    return key
def encrypt_string(content):
    key = settings.FERNET_KEY.encode() 
    fernet = Fernet(key)
    encrypted_content = fernet.encrypt(content.encode())
    return encrypted_content.decode() 

def decrypt_string(encrypted_content):
    #key = Fernet.generate_key()
    key = settings.FERNET_KEY.encode()
    fernet = Fernet(key)
    encoded_encrypted_content = encrypted_content.encode()
    decrypted_content = fernet.decrypt(encoded_encrypted_content).decode()
    return decrypted_content

def create_token(length=64):
    token = secrets.token_urlsafe(length)
    return token
def create_email_pin(email):
    token = secrets.token_urlsafe(64)
    encrypted_pin= encrypt_string(generate_pin())
    decrypted_pin= decrypt_string(encrypted_pin)
    email_pin = models.EmailPin.objects.create(verify_key=token, email=email, pin_code=encrypted_pin,expiry=datetime.datetime.now()+datetime.timedelta(minutes=10))
    return email_pin


def send_email_pin(email_pin_obj):
    try:
       subject = 'Your email pin verification for: [system name]'
       template = 'email/pin_code.html'
       cc = None
       bcc = None
       from_email = None
       context= {'context_processor': {}, 'signature': 'off', 'email_pin_obj' : email_pin_obj, 'pin_code_decrypted': decrypt_string(email_pin_obj.pin_code)}
       to = email_pin_obj.email
       template_group = "system-oim"
       emails.sendHtmlEmail([to],subject,context,template,cc,bcc,from_email,template_group,attachments=[])
    except:
       print("error sending email")
       return False
    return True
