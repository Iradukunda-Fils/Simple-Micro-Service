from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
import uuid
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField
from django_countries.fields import CountryField
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(email, password, **extra_fields)

class User(PermissionsMixin, AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(_("User Name"), max_length=50)
    email = models.EmailField(_("Email Address"), unique=True)
    first_name = models.CharField(_("First Name"), max_length=30, blank=True)
    last_name = models.CharField(_("Last Name"), max_length=30, blank=True)
    is_staff = models.BooleanField(_("Staff Status"), default=False)
    is_active = models.BooleanField(_("Active"), default=False)
    last_password_change = models.DateTimeField(_("Last Password Change"), default=timezone.now, null=True, blank=True)
    last_login = models.DateTimeField(_("Last Login"), null=True, blank=True, editable=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile', verbose_name=_("User"))
    date_joined = models.DateTimeField(_("Date Joined"), auto_now_add=True)
    business_name = models.CharField(_("Business Name"), max_length=255, blank=True)
    country = CountryField(_("Country"), blank_label=_('(select country)'), blank=True, null=True)
    phone_number = PhoneNumberField(_("Phone Number"), blank=True, null=True, region='RW')
    address = models.CharField(_("Address"), max_length=255, blank=True)
    website = models.URLField(_("Website"), blank=True)
    bio = models.TextField(_("Bio"), blank=True)
    

    def __str__(self):
        return f"{self.user.email} " + _("Profile")