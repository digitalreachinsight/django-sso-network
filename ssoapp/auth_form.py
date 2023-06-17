from django.contrib.auth import forms
from django.contrib.auth import (
    authenticate, get_user_model, password_validation,
)
from crispy_forms.layout import Layout, Submit, HTML, Fieldset, MultiField, Div, Button, Submit
from django.forms import CharField
from crispy_forms.helper import FormHelper
from django_crispy_jcaptcha.widget import CaptchaImages, CaptchaValidation

from . import models

UserModel = get_user_model()

class BaseFormHelper(FormHelper):
    form_class = 'form-horizontal'
    label_class = 'col-xs-12 col-sm-4 col-md-3 col-lg-2'
    field_class = 'col-xs-12 col-sm-8 col-md-6 col-lg-4'

class AuthenticationForm(forms.AuthenticationForm):

    captcha = CharField(required=True,widget=CaptchaImages(attrs={}))

    def __init__(self, request=None, *args, **kwargs):
        """
        The 'request' parameter is set for custom auth use by subclasses.
        The form data comes in via the standard 'data' kwarg.
        """
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)
        self.helper = BaseFormHelper()
       
        # Set the max length and label for the "username" field.
        self.username_field = UserModel._meta.get_field(UserModel.USERNAME_FIELD)
        username_max_length = self.username_field.max_length or 254
        self.fields['username'].max_length = username_max_length
        self.fields['username'].widget.attrs['maxlength'] = username_max_length
        if self.fields['username'].label is None:
            self.fields['username'].label = capfirst(self.username_field.verbose_name)

        self.fields['username'].widget.attrs.update({'class': 'form-control'})
        self.fields['password'].widget.attrs.update({'class': 'form-control'})
        self.helper.layout = Layout(HTML('<h1 class="h3 mb-3 font-weight-normal">Login</h1>'),'username','password','captcha',Submit('sso-login', 'Login', css_class="btn btn-primary"))

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username is not None and password:
            self.user_cache = authenticate(self.request, username=username, password=password)
            if self.user_cache is None:
                raise self.get_invalid_login_error()
            else:
                self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data

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

