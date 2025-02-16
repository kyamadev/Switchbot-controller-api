from django.db import models
from django.conf import settings

class SwitchBotCredential(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='switchbot_credential'
    )
    token = models.CharField(max_length=255)
    secret = models.CharField(max_length=255)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"SwitchBotCredential for {self.user}"