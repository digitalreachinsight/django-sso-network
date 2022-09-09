from django import forms
from ssoapp import models
from ssoapp import utils
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, HTML, Fieldset, MultiField, Div, Button
from django.forms import Form, ModelForm, ChoiceField, FileField, CharField, Textarea, ClearableFileInput, HiddenInput, Field, RadioSelect, ModelChoiceField, Select, CheckboxInput
from django_crispy_jcaptcha.widget import CaptchaImages, CaptchaValidation
import datetime
import dns.resolver
import socket
import re
import pyotp

class BaseFormHelper(FormHelper):
    form_class = 'form-horizontal'
    label_class = 'col-xs-12 col-sm-4 col-md-3 col-lg-2'
    field_class = 'col-xs-12 col-sm-8 col-md-6 col-lg-4'

class OTPForm(forms.ModelForm):
    email_address = forms.CharField(widget=forms.TextInput(attrs={'required':True, 'class': "form-control"}), label="Email Address" )
    pin_code = forms.CharField(widget=forms.TextInput(attrs={'required':True, 'class': "form-control",}), label="Enter OTP Pin Code", required=False, max_length=6)
    captcha = CharField(required=True,widget=CaptchaImages(attrs={}))

    class Meta:
        model = models.EmailUser
        fields = []

    def __init__(self, *args, **kwargs):
        # User must be passed in as a kwarg.
        super(OTPForm, self).__init__(*args, **kwargs)
        self.helper = BaseFormHelper()
        self.helper.form_id = 'id_otp_form'
        self.helper.add_input(Submit('Verify Pin', 'Verify Pin', css_class='btn-lg', style='margin-top: 15px;' ))
        html_top_message = "<br><div style='background-color:#ededed; padding: 8px; border-radius: 5px 5px 5px 5px; '>To login to your account please enter your email address, your one OTP (from your key fob or app and select the matching captcha image.</div><br>"
        self.helper.layout = Layout(HTML(html_top_message),'email_address','pin_code','captcha',)


    def clean_email_address(self):
         print ("clean_email_address")
         email_address = self.cleaned_data['email_address']
         print ("validating email address")
         email_regex = re.compile(r'([A-Za-z0-9]+[.-_+])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
         if re.fullmatch(email_regex, email_address):
             pass
         else:
             raise forms.ValidationError('Email address format is not valid.')
         print (self.cleaned_data['email_address'])

         email_address = email_address.split("@")
         try:
             #print ("TRYING")
             #print (email_address[1])
             #socket.getaddrinfo(email_address[1], None)
             answers = dns.resolver.resolve(email_address[1], "MX")
             #for rdata in answers:
             #    #print("Host", rdata.exchange, "has preference", rdata.preference)
             #    pass

         except Exception as e:
             print (e)
             raise forms.ValidationError('Email address domain name does not exist.')

         return self.cleaned_data['email_address']


    def clean_captcha(self):
         CaptchaValidation(self.cleaned_data['captcha'], forms)
         return self.cleaned_data['captcha']

    def clean_pin_code(self):
        
        otp_match = False
        if 'email_address' in self.cleaned_data:
            email_otp = models.EmailOTP.objects.filter(email__email=self.cleaned_data['email_address'])
            if email_otp.count() > 0:
                for eotp in email_otp:
                    totp = pyotp.TOTP(eotp.otp_key)
                    
                    try:
                        if totp.now() == self.cleaned_data['pin_code']:
                             otp_match = True
                    except:
                        print ("token base32 error")

                if otp_match is True:
                     return self.cleaned_data['pin_code']
                else:
                     raise forms.ValidationError('Invalid OTP pin code')


            else:
                raise forms.ValidationError('Invalid OTP pin code')
        else:
            raise forms.ValidationError('Invalid OTP pin code')






class EmailPinForm(forms.ModelForm):
    email_address = forms.CharField(widget=forms.TextInput(attrs={'required':True, 'class': "form-control"}), label="Email Address" )
    captcha = CharField(required=True,widget=CaptchaImages(attrs={}))

    class Meta:
        model = models.EmailUser
        fields = []

    def __init__(self, *args, **kwargs):
        # User must be passed in as a kwarg.
        super(EmailPinForm, self).__init__(*args, **kwargs)
        self.helper = BaseFormHelper()
        #for f in self.fields:
        #   self.fields[f].widget.attrs.update({'class': 'form-control'})
        self.helper.form_id = 'id_email_pin_form'
        self.helper.add_input(Submit('Send PIN to Email', 'Send PIN to Email', css_class='btn-lg', style='margin-top: 15px;' ))
        html_top_message = "<br><div style='background-color:#ededed; padding: 8px; border-radius: 5px 5px 5px 5px; '>To login to your account please enter your email address and select the matching captcha image. You will than be sent a PIN Code to you email account which you can use to enter on the next screen which will log you into your account.</div><br>"
        self.helper.layout = Layout(HTML(html_top_message),'email_address','captcha',)

    def clean_email_address(self):
         print ("clean_email_address")
         email_address = self.cleaned_data['email_address']
         print ("validating email address")
         email_regex = re.compile(r'([A-Za-z0-9]+[.-_+])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
         if re.fullmatch(email_regex, email_address):
             pass 
         else:
             raise forms.ValidationError('Email address format is not valid.')
         print (self.cleaned_data['email_address'])

         email_address = email_address.split("@")
         try:
             #print ("TRYING")
             #print (email_address[1])
             #socket.getaddrinfo(email_address[1], None)
             answers = dns.resolver.resolve(email_address[1], "MX")
             #for rdata in answers:
             #    #print("Host", rdata.exchange, "has preference", rdata.preference)
             #    pass

         except Exception as e:
             print (e)
             raise forms.ValidationError('Email address domain name does not exist.')

         return self.cleaned_data['email_address']


    def clean_captcha(self):
         CaptchaValidation(self.cleaned_data['captcha'], forms)
         return self.cleaned_data['captcha']

class VerifyEmailPinForm(forms.ModelForm):

    first_name = forms.CharField(widget=forms.TextInput(attrs={'required':False, 'class': "form-control",}), label="First Name", required=False)
    last_name = forms.CharField(widget=forms.TextInput(attrs={'required':False, 'class': "form-control",}), label="Last Name", required=False)
    verify_key_link = forms.CharField(widget=forms.HiddenInput(), required=False)
    email_pin_code = forms.CharField(widget=forms.TextInput(attrs={'required':True, 'class': "form-control",}), label="Enter PIN Code", required=False, max_length=6)

    class Meta:
        model = models.EmailPin
        fields = []

    def __init__(self, *args, **kwargs):
        # User must be passed in as a kwarg.
        super(VerifyEmailPinForm, self).__init__(*args, **kwargs)
        print ("FORM ARH")
        print (kwargs)
        self.helper = BaseFormHelper()
        print ("NAME EXISTS")
        html_top_message = '<b>Please provide your first name, last name and enter the pin code sent to your email account.</B><br><br>'
        html_middle_message = "<hr>"
        first_name_field = Fieldset('','first_name')
        if 'name_exists' in self.initial:
            if self.initial['name_exists'] is True:
                 del self.fields['first_name']
                 del self.fields['last_name']
                 html_top_message = '<b>Please enter the pin code sent to your email account.</B><br><br>'
                 html_middle_message = ''
            else:
                self.fields['first_name'].required=True
                self.fields['last_name'].required=True


        print (self.initial['name_exists'])
        #for f in self.fields:
        #   self.fields[f].widget.attrs.update({'class': 'form-control'})
        self.helper.form_id = 'id_email_pin_form'
        self.helper.add_input(Submit('Verify PIN', 'Verify PIN', css_class='btn-lg', style='margin-top: 15px;' ))
        #if self.initial['name_exists'] is True:
        #self.helper.layout = Layout(HTML(html_top_message),'verify_key_link',HTML(html_middle_message),'email_pin_code')
        #else:
        self.helper.layout = Layout(HTML(html_top_message),'first_name','last_name','verify_key_link',HTML(html_middle_message),'email_pin_code')

    def clean_verify_key_link(self):
        return self.cleaned_data['verify_key_link']

    def clean_email_pin_code(self):
        verify_key = self.cleaned_data['verify_key_link']
        pin_code_entered = self.cleaned_data['email_pin_code']

        ep = models.EmailPin.objects.filter(verify_key=verify_key, status='notactivated',  expiry__gte=datetime.datetime.now())
        email_pin_obj = None
        if ep.count() > 0:
            email_pin_obj = ep[0]
        else:
            raise forms.ValidationError('Your verification code has expired or no longer exists.')
        
        pin_code_decrypted = utils.decrypt_string(email_pin_obj.pin_code)
        if pin_code_decrypted == pin_code_entered:
             pass
        else:
            raise forms.ValidationError('The pin code you entered was incorrect.')
        return self.cleaned_data['email_pin_code']





