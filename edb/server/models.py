from django.db import models

from edb.server.util import match

class EncryptedManager(models.Manager):
    """Object manager for encrypted models."""
    def encrypted_filter(self, **queries):
        """Filter on encrypted data."""
        return [model for model in self.all()
                if all(match(getattr(model, field_name, None), query)
                       for field_name, query in queries.items())]

class EncryptedModel(models.Model):
    """Abstract base class for an encrypted model."""
    objects = EncryptedManager()

    class Meta:
        abstract = True

class _Ping(EncryptedModel):
    """Concrete model for test cases."""
    source = models.BinaryField()
    destination = models.BinaryField()
