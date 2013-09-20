from django.db import models

from django.utils.translation import ugettext_lazy as _
from django.utils import timezone

from django.contrib.auth.models import AbstractNamedUser

class EmailUser(AbstractNamedUser):
    """
    An abstract user model that is an alternative to the standard AbstractUser.  The 
    sole difference is that AbstractEmailUser does not have a username field, and uses 
    the email field as the primary identifier by default.

    Email and password are required. Other fields are optional.
    """

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta(AbstractNamedUser.Meta):
        pass

    def get_absolute_url(self):
        return "/users/%s/" % urlquote(self.pk)
