from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager
)
import uuid
import secrets


class ServiceAccountManager(BaseUserManager):
    
    def create_user(self, name, service_key=None, **extra_fields):
        
        if not name:
            raise ValueError('The service must have a name.')
    
        service_type = extra_fields.get('service_type')
        if not service_type:
            raise ValueError('The service must have a service_type.')
    
        api_key = extra_fields.get('api_key') or secrets.token_urlsafe(32)
        extra_fields['api_key'] = api_key
    
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_staff', False)
    
        service = self.model(name=name, **extra_fields)
    
        service.set_password(service_key)
    
        service.save(using=self._db)
        return service

    def create_superuser(self, name, service_key=None, **extra_fields):
        """
        Creates and saves a superuser ServiceAccount with the given name and service_key.
        """
        if not name:
            raise ValueError('The service must have a name.')

        # Ensure api_key is always set
        api_key = extra_fields.get('api_key') or secrets.token_urlsafe(32)
        extra_fields['api_key'] = api_key

        # Set required superuser fields
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)

        service = self.model(name=name, **extra_fields)

        service.set_password(service_key)

        service.save(using=self._db)
        return service    
        

# Base Microservice Model
class ServiceAccount(PermissionsMixin, AbstractBaseUser):
    SERVICE_TYPES = [
        ('auth', 'Authentication Service'),
        ('user', 'User Management'),
        ('media', 'Media Storage'),
        ('payment', 'Payment Gateway'),
        ('email', 'Email Notification'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150, unique=True)
    service_type = models.CharField(max_length=50, default="user", choices=SERVICE_TYPES)
    is_staff = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True, editable=False)

    # Optional secure field 
    api_key = models.CharField(max_length=255, blank=True, null=True)
    
    USERNAME_FIELD = 'name'
    REQUIRED_FIELDS = []

    objects = ServiceAccountManager()

    def __str__(self):
        return self.name
