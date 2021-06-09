import base64
from collections import namedtuple

from cryptography.fernet import Fernet

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class OIDCConfig(models.Model):
    """
    OIDC variables used by mozilla_django_oidc
    """
    name = models.TextField(unique=True, db_index=True)
    description = models.TextField(null=True, blank=True)

    OIDC_RP_CLIENT_ID = models.TextField()
    OIDC_RP_CLIENT_SECRET = models.TextField()

    OIDC_OP_AUTHORIZATION_ENDPOINT = models.TextField()
    OIDC_OP_TOKEN_ENDPOINT = models.TextField()
    OIDC_OP_USER_ENDPOINT = models.TextField()
    OIDC_AUTH_REQUEST_EXTRA_PARAMS = models.TextField(null=True, blank=True)

    OIDC_RP_SIGN_ALGO = models.TextField(null=True, blank=True)
    OIDC_RP_IDP_SIGN_KEY = models.TextField(null=True, blank=True)
    OIDC_OP_JWKS_ENDPOINT = models.TextField(null=True, blank=True)

    def set_client_secret(self, secret):
        self.OIDC_RP_CLIENT_SECRET = self._fernet.encrypt(secret.encode()).decode()

    def get_client_secret(self):
        return self._fernet.decrypt(self.OIDC_RP_CLIENT_SECRET.encode()).decode()

    def as_config(self):
        oidc_fields = [x.name for x in self._meta.fields if x.name.startswith('OIDC')]
        data = {x: getattr(self, x) for x in oidc_fields}
        data['OIDC_RP_CLIENT_SECRET'] = self.get_client_secret()
        Config = namedtuple('Config', oidc_fields)
        return Config(**data)

    def save(self, *args, **kwargs):
        if (self.OIDC_RP_SIGN_ALGO and self.OIDC_RP_SIGN_ALGO.startswith('RS') and
                (self.OIDC_RP_IDP_SIGN_KEY is None and self.OIDC_OP_JWKS_ENDPOINT is None)):
            raise ValidationError(f'{self.OIDC_RP_SIGN_ALGO} alg requires OIDC_RP_IDP_SIGN_KEY or '
                                  f'OIDC_OP_JWKS_ENDPOINT to be configured.')

        for field in self._meta.fields:
            if not getattr(self, field.name):
                setattr(self, field.name, None)

        super().save(*args, **kwargs)

    @property
    def _fernet(self):
        return Fernet(base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode()))

    def __str__(self):
        return self.name
