from django.contrib import admin
from django.db import models
from django import forms


from .models import OIDCConfig

@admin.register(OIDCConfig)
class OIDCConfigAdmin(admin.ModelAdmin):
    formfield_overrides = {
        models.TextField: {'widget': forms.TextInput(attrs={'class': 'vTextField'})}
    }

    def get_form(self, request, obj=None, **kwargs):
        if obj and not getattr(obj, 'decrypted', False):
            obj.OIDC_RP_CLIENT_SECRET = obj.get_client_secret()
            obj.decrypted = True
        return super().get_form(request, obj, **kwargs)

    def save_model(self, request, obj, form, change):
        obj.set_client_secret(obj.OIDC_RP_CLIENT_SECRET)
        super().save_model(request, obj, form, change)

