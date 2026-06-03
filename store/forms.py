from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=100, required=True)
    last_name = forms.CharField(max_length=100, required=True)

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name", "password1", "password2"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for _, field in self.fields.items():
            field.widget.attrs.update({"class": "form-control"})


class CheckoutForm(forms.Form):
    full_name = forms.CharField(max_length=160)
    email = forms.EmailField()
    address = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}))
    city = forms.CharField(max_length=80)
    postal_code = forms.CharField(max_length=20)
    card_name = forms.CharField(max_length=120)
    card_number = forms.CharField(max_length=25)
    expiry = forms.CharField(max_length=7)
    cvv = forms.CharField(max_length=4)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for _, field in self.fields.items():
            field.widget.attrs.update({"class": "form-control"})
