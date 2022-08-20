from django.shortcuts import render
from django import template
from django.template import loader
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden
from django.urls import reverse
from django.views.generic import TemplateView, ListView, DetailView, CreateView, UpdateView, DeleteView, FormView
from django.conf import settings
from django.contrib.auth import login, logout, get_user_model
import os
import re
from django.utils.crypto import get_random_string
from django.contrib import messages
from django.template.loader import get_template
from django.middleware.csrf import get_token
from ssoapp import models
from ssoapp import forms as app_forms
from ssoapp import context_processors
from ssoapp import utils
from django.conf import settings
import string
import random
import datetime
import requests


#class HomePage(TemplateView):
#    # preperation to replace old homepage with screen designs..
#
#    template_name = 'home_page.html'
#    def render_to_response(self, context):
#
#        #if self.request.user.is_authenticated:
#        #   if len(self.request.user.first_name) > 0:
#        #       donothing = ''
#        #   else:
#        #       return HttpResponseRedirect(reverse('first_login_info_steps', args=(self.request.user.id,1)))
#        template = get_template(self.template_name)
#        
#        #context = RequestContext(self.request)
#        context['request'] = self.request
#        context['csrf_token_value'] = get_token(self.request)
#        context['sso_auth_session_id'] = self.request.COOKIES.get('sso_auth_session_id','')
#        context['referer'] = self.request.GET.get('referer',None)
#        return HttpResponse(template.render(context))
#
#    def get_context_data(self, **kwargs):
#        context = super(HomePage, self).get_context_data(**kwargs)
#        context = context_processors.template_variables(self.request)
#        context['request'] = self.request
#        context['user'] = self.request.user
#        if self.request.user.is_staff is True:
#           context['staff'] = self.request.user.is_staff
#        else:
#           context['staff'] = False
#        #context = template_context(self.request)
#        return context
class LoginSuccess(TemplateView):
    template_name = 'login_success.html'
     

class HomePage(CreateView):
    template_name = 'home_page.html'
    model = models.EmailUser 

    def get(self, request, *args, **kwargs):
        #context_processor = template_context(self.request)
        return super(HomePage, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(HomePage, self).get_context_data(**kwargs)
        context['query_string'] = ''
        context['sso_auth_session_id'] = self.request.COOKIES.get(settings.SESSION_COOKIE_NAME,'')
        context['referer'] = self.request.GET.get('referer',None)
        return context

    def get_initial(self):
        initial = super(HomePage, self).get_initial()
        request = self.request
        return initial

    def get_form_class(self):
        return app_forms.EmailPinForm

    def post(self, request, *args, **kwargs):
        #if request.POST.get('cancel'):
        #    return HttpResponseRedirect(self.get_absolute_url())
        return super(HomePage, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        self.object = form.save(commit=False)
        forms_data = form.cleaned_data
        email_pin = utils.create_email_pin(forms_data['email_address'])
        send_email = utils.send_email_pin(email_pin)
        return HttpResponseRedirect('verify/email-pin/'+email_pin.verify_key)

class OTPSignIn(CreateView):
    template_name = 'sign_in_otp.html'
    model = models.EmailUser

    def get(self, request, *args, **kwargs):
        #context_processor = template_context(self.request)
        return super(OTPSignIn, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(OTPSignIn, self).get_context_data(**kwargs)
        context['query_string'] = ''
        return context

    def get_initial(self):
        initial = super(OTPSignIn, self).get_initial()
        request = self.request
        return initial

    def get_form_class(self):
        return app_forms.OTPForm

    def post(self, request, *args, **kwargs):
        #if request.POST.get('cancel'):
        #    return HttpResponseRedirect(self.get_absolute_url())
        return super(OTPSignIn, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        self.object = form.save(commit=False)
        forms_data = form.cleaned_data

        eu = models.EmailUser.objects.filter(email=forms_data['email_address'])
        email_user = None
        if eu.count() > 0:
              email_user = models.EmailUser.objects.get(email=forms_data['email_address'])

        email_user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(self.request, email_user)

        return HttpResponseRedirect(reverse('login-succes'))


class EmailPinSignIn(CreateView):
    template_name = 'sign_in_email_pin.html'
    model = models.EmailUser

    def get(self, request, *args, **kwargs):
        #context_processor = template_context(self.request)
        return super(EmailPinSignIn, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(EmailPinSignIn, self).get_context_data(**kwargs)
        context['query_string'] = ''
        return context

    def get_initial(self):
        initial = super(EmailPinSignIn, self).get_initial()
        request = self.request
        return initial

    def get_form_class(self):
        return app_forms.EmailPinForm

    def post(self, request, *args, **kwargs):
        #if request.POST.get('cancel'):
        #    return HttpResponseRedirect(self.get_absolute_url())
        return super(EmailPinSignIn, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        self.object = form.save(commit=False)
        forms_data = form.cleaned_data
        email_pin = utils.create_email_pin(forms_data['email_address'])
        send_email = utils.send_email_pin(email_pin)
        return HttpResponseRedirect('/verify/email-pin/'+email_pin.verify_key)


class VerifyEmailPIN(CreateView):
    template_name = 'verify_email_pin.html'
    model = models.EmailPin
    verify_key_url = None
    account_exists = False
    name_exists = False

    def get(self, request, *args, **kwargs):
        self.request = request
        self.verify_key_url = kwargs['verify_key']
        return super(VerifyEmailPIN, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(VerifyEmailPIN, self).get_context_data(**kwargs)

        if self.verify_key_url is None:
           pass
        else:
           ep = models.EmailPin.objects.filter(verify_key=self.verify_key_url, status='notactivated',  expiry__gte=datetime.datetime.now())
           if ep.count() > 0:
              #eu = models.EmailUser.objects.filter(email=ep[0].email)
              #if eu.count() > 0:
              #    self.account_exists = True
              #    email_user = eu[0]
              #    print ("NAME LENGTH")
              #    print (len(email_user.first_name))
              #    print (len(email_user.last_name))
              #    if len(email_user.first_name) > 0 and len(email_user.last_name) > 0:
              #         self.name_exists = True

              #          
              pass
           else:
              self.template_name = 'verify_email_pin_error.html'
              context['error']  = "No verification key was not found or the key has expired."
        return context

    def get_initial(self):
        ep = models.EmailPin.objects.filter(verify_key=self.verify_key_url, status='notactivated',  expiry__gte=datetime.datetime.now())
        if ep.count() > 0:
            eu = models.EmailUser.objects.filter(email=ep[0].email)
            if eu.count() > 0:
                self.account_exists = True
                email_user = eu[0]
                if len(email_user.first_name) > 0 and len(email_user.last_name) > 0:
                    self.name_exists = True


        initial = super(VerifyEmailPIN, self).get_initial()
        if self.verify_key_url is None:
            pass
        else:
            initial['verify_key_link'] = self.verify_key_url
        initial['account_exists'] = self.account_exists 
        initial['name_exists'] = self.name_exists
        return initial

    def get_form_class(self):
        return app_forms.VerifyEmailPinForm

    def post(self, request, *args, **kwargs):
        self.verify_key_url = request.POST.get('verify_key_link', None)
        #if request.POST.get('cancel'):
        #    return HttpResponseRedirect(self.get_absolute_url())
        return super(VerifyEmailPIN, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        self.object = form.save(commit=False)
        forms_data = form.cleaned_data

        ep = models.EmailPin.objects.get(verify_key=forms_data['verify_key_link'])
        ep.status = 'activated'
        ep.save()
        eu = models.EmailUser.objects.filter(email=ep.email)
        email_user = None
        if eu.count() > 0:
              email_user = models.EmailUser.objects.get(email=ep.email)
              if 'first_name' in forms_data and 'last_name' in forms_data:
                  email_user.first_name = forms_data['first_name']
                  email_user.last_name = forms_data['last_name']
                  email_user.save()
        else:
            email_user = models.EmailUser.objects.create(email=ep.email, first_name=forms_data['first_name'], last_name=forms_data['last_name'])

        email_user.backend = 'django.contrib.auth.backends.ModelBackend'
        #request.session.set_expiry(SESSION_EXPIRY_SSO)
        login(self.request, email_user)

        return HttpResponseRedirect(reverse('login-succes'))


def CheckAuth(request):
     text = request.COOKIES.get('session','')
     cookie_session = request.COOKIES.get(settings.SESSION_COOKIE_NAME,'')
     get_session = request.GET.get('sso_auth_session_id',None)
     referer = request.GET.get('referer','')

     session_id = None
     if get_session:
           session_id = get_session

     if request.user.is_authenticated:
         response = HttpResponse('Authenticated', content_type='text/plain', status=200)
         response['X-TestUser'] = 'test@test.com'
         if get_session:
               response.set_cookie(settings.SESSION_COOKIE_NAME, get_session, max_age=sess.expiry,expires=sess.expiry)
               response = HttpResponseRedirect(referer)
     else:
         response = HttpResponse('Unable to find valid session', content_type='text/plain', status=403)
     return response

from django.views.decorators.csrf import csrf_exempt

# Session Verification
@csrf_exempt
def Auth(request):
     print ("TRYING")
     print (request.META)

     text = request.COOKIES.get('session','')
     cookie_session = request.COOKIES.get(settings.SESSION_COOKIE_NAME,'')
     get_session = request.GET.get('sso_auth_session_id',None)
     referer = request.GET.get('referer','')

     session_id = None
     print (loader.render_to_string( 'cookie_session.html', {'title': "TEWST", 'cal': "CAL:"}))
     if get_session:
           session_id = get_session
           cs = loader.render_to_string( 'cookie_session.html', {'referer': referer})
           response = HttpResponse(cs, content_type='text/html', status=200)
           response.set_cookie(settings.SESSION_COOKIE_NAME, get_session ) 

           #response = HttpResponseRedirect(referer)
           return response
     else:
           session_id = cookie_session

     if request.user.is_authenticated: 
         response = HttpResponse('Authenticated', content_type='text/plain', status=200)
        
         response['X-TestUser'] = 'test@test.com'
         response['X-REMOTEUSER'] = request.user.email 
         response['X-LASTNAME'] = request.user.last_name
         response['X-FIRSTNAME'] = request.user.first_name
         response['X-EMAIL'] = request.user.email 

         if get_session:
               response.set_cookie('sso_auth_session_id', get_session )
               response = HttpResponseRedirect(referer)
     else:
         response = HttpResponse('Unable to find valid session', content_type='text/plain', status=403)
         response['X-TOKENID'] = '093098124098312089kjaslkjjflkdas'

     print (response)
     print ("5")
     return response

@csrf_exempt
def AuthRedirect(request):
     print ("TRYING")
     print (request.META.get('HTTP_REFERER', None))
     print (request.META)
     print ("END OF TRYING")

     REFERAL_URL=request.META.get('HTTP_REFERER', None)
     HTTP_HOST=request.META.get('HTTP_HOST',None)
     DEFAULT_URL=settings.DEFAULT_URL
     text = request.COOKIES.get('session','')
     cookie_session = request.COOKIES.get('sso_auth_session_id','')
     get_session = request.GET.get('sso_auth_session_id',None)
     referer = request.GET.get('referer','')

     session_id = None
     #print (loader.render_to_string( 'cookie_session.html', {'title': "TEWST", 'cal': "CAL:"}))
     if get_session:
           session_id = get_session
           cs = loader.render_to_string( 'cookie_session.html', {'referer': referer})
           response = HttpResponse(cs, content_type='text/html', status=200)
           response.set_cookie('sso_auth_session_id', get_session )

           #response = HttpResponseRedirect(referer)
           return response
     else:
           session_id = cookie_session

     if request.user.is_authenticated:
         response = HttpResponse('Authenticated', content_type='text/plain', status=200)

         response['X-TestUser'] = 'test@test.com'
         response['X-REMOTEUSER'] = request.user.email
         response['X-LASTNAME'] = request.user.last_name
         response['X-FIRSTNAME'] = request.user.first_name
         response['X-EMAIL'] = request.user.email

         if get_session:
               response.set_cookie('sso_auth_session_id', get_session)
               response = HttpResponseRedirect(referer)
     else:
         redirect_token = 'GJHLKLKGJHD679797980987dsafasdfads'
         domain_group = None
         dg = models.DomainGroup.objects.all()

         for d in dg:
             pattern = re.compile(d.domain)
             print (d.domain)
             if pattern.match(HTTP_HOST):
                  domain_group = d
                  print ("TRUE")
             else:
                 print ("FALSE")

         token_id = utils.create_token(64)
         models.AuthRedirect.objects.create(redirect_token=token_id,expiry=datetime.datetime.now()+datetime.timedelta(minutes=60), domain_group=domain_group)
         #AuthRedirect
         response = HttpResponse('Preparing to direct .... '+token_id+' <script>window.location.href="'+DEFAULT_URL+'?auth_token='+redirect_token+'";</script>', content_type='text/html', status=200)
         response['X-TOKENID'] = '093098124098312089kjaslkjjflkdas'

     return response


from django.contrib.auth import logout

def sso_logout(request):
    your_data = request.session.get('your_key', None)
    current_expiry = request.session.get('_session_expiry')
    logout(request)
    if your_data:
        request.session[settings.SESSION_COOKIE_NAME] = your_data
        if current_expiry:
           request.session['_session_expiry'] = current_expiry
    response = HttpResponse('<script>window.location="/";</script>', content_type='text/html', status=200)
    return response

def logout_old(request):
    """
    Removes the authenticated user's ID from the request and flushes their
    session data.
    """
    # Dispatch the signal before the user is logged out so the receivers have a
    # chance to find out *who* logged out.
    user = getattr(request, 'user', None)
    if hasattr(user, 'is_authenticated') and not user.is_authenticated():
        user = None
    user_logged_out.send(sender=user.__class__, request=request, user=user)

    request.session.flush()
    if hasattr(request, 'user'):
        from django.contrib.auth.models import AnonymousUser
        request.user = AnonymousUser()




     #session_id = None
     #if get_session:
     #    session_id = get_session
     #else:
     #    session_id = cookie_session
     #request.headers['X-TestUser'] = 'jason@austwa.com'

#     if models.SMSSession.objects.filter(session=session_id, expiry__gte=datetime.datetime.now()).count() > 0:
#         sess = models.SMSSession.objects.filter(session=session_id)[0]
#         response = HttpResponse(text, content_type='text/plain', status=200)
#         response['X-TestUser'] = 'jason@austwa.comiii'
#         if get_session:
#             response = HttpResponseRedirect(referer)
#             response.set_cookie('sso_auth_session_id', get_session, max_age=sess.expiry,expires=sess.expiry)
#     else:
#         response = HttpResponse('Unable to find valid session', content_type='text/plain', status=403)
#     return response
#


