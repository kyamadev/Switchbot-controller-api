from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet
import base64
import os
from django.core.exceptions import ImproperlyConfigured

class EncryptedField(models.CharField):
    """
    Custom field that encrypts values before saving to the database
    and decrypts when retrieving from the database.
    """
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 500
        super().__init__(*args, **kwargs)

    def get_key(self):
        """Get the encryption key from settings, or generate one if not available."""
        key = getattr(settings, 'ENCRYPTION_KEY', None)
        if key is None:
            if not settings.DEBUG:
                raise ImproperlyConfigured("ENCRYPTION_KEY must be set in production")
            key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        return key

    def get_cipher(self):
        """Create a Fernet cipher using the encryption key."""
        key = self.get_key()
        return Fernet(key.encode() if isinstance(key, str) else key)

    def from_db_value(self, value, expression, connection):
        """Decrypt value when retrieving from the database."""
        if value is None:
            return value
        try:
            cipher = self.get_cipher()
            return cipher.decrypt(value.encode()).decode()
        except Exception as e:
            print(f"Error decrypting value: {e}")
            return value

    def to_python(self, value):
        """Convert the value from the database to a Python object."""
        if value is None:
            return value
        return value

    def get_prep_value(self, value):
        """Encrypt value before saving to the database."""
        if value is None:
            return value
        try:
            cipher = self.get_cipher()
            return cipher.encrypt(value.encode()).decode()
        except Exception as e:
            print(f"Error encrypting value: {e}")
            return value


class SwitchBotCredential(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='switchbot_credential'
    )
    token = EncryptedField()
    secret = EncryptedField()
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"SwitchBotCredential for {self.user}"