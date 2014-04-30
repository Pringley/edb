from django.db import models

from edb.server.models import EncryptedModel

class Packet(EncryptedModel):
    source = models.CharField(max_length=700)
    destination = models.CharField(max_length=700)
    protocol = models.CharField(max_length=700)
    length = models.CharField(max_length=700)
