import uuid
from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager
)

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
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
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

class BankUser(PermissionsMixin, AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    phone_number = PhoneNumberField(blank=True, null=True, region='RW')
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()
    
    class meta:
        verbose_name = 'users'
        ordering = ['email', 'date_joined']


class EmployeeProfile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Link to User
    user = models.OneToOneField(BankUser, on_delete=models.CASCADE, related_name='employee_profile')

    # Employment Info
    employee_id = models.CharField(max_length=20, unique=True)
    department = models.CharField(max_length=100)
    role = models.CharField(max_length=100)
    date_hired = models.DateField()
    work_location = models.CharField(max_length=255)

    # Identification
    national_id = models.CharField(max_length=20, unique=True)
    passport_number = models.CharField(max_length=20, blank=True, null=True)

    # Emergency Contact
    emergency_contact_name = models.CharField(max_length=100)
    emergency_contact_phone = PhoneNumberField(blank=True, null=True, region='RW')
    relationship_to_emergency_contact = models.CharField(max_length=50)

    # Security & Compliance
    is_background_checked = models.BooleanField(default=False)
    has_signed_confidentiality_agreement = models.BooleanField(default=False)
    access_level = models.CharField(max_length=50, default='standard')  # e.g., 'admin', 'standard', 'limited'

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.get_full_name()} ({self.employee_id})"

    class Meta:
        db_table = 'bank_employee_profiles'
        verbose_name = 'Employee Profile'
        verbose_name_plural = 'Employee Profiles'
    
        indexes = [
            models.Index(fields=['employee_id']),
            models.Index(fields=['national_id']),
            models.Index(fields=['user']),
        ]

