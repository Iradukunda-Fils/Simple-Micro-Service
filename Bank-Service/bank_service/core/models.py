"""
Professional Bank System Django Models
Implementing industry-standard fintech practices with advanced security,
audit trails, compliance, and scalability considerations.
"""
import uuid
from decimal import Decimal
from datetime import datetime, timezone
from django.db import models, transaction
from django.contrib.auth import get_user_model
from phonenumber_field.modelfields import PhoneNumberField
from django_countries.fields import CountryField
from django.core.validators import (
    RegexValidator, MinValueValidator, MaxValueValidator
    )
import hashlib
from cryptography.fernet import Fernet

User = get_user_model()

class TimestampedModel(models.Model):
    """
    Abstract base class providing timestamp fields with timezone awareness
    and soft delete functionality for audit compliance.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        abstract = True
    
    def soft_delete(self):
        """Soft delete implementation for regulatory compliance"""
        self.is_active = False
        self.deleted_at = timezone.now()
        self.save(update_fields=['is_active', 'deleted_at'])


class AuditableModel(TimestampedModel):
    """
    Enhanced audit model for financial transactions requiring
    immutable audit trails and regulatory compliance.
    """
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_%(class)s')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='updated_%(class)s')
    version = models.PositiveIntegerField(default=1)
    checksum = models.CharField(max_length=64, blank=True)
    
    class Meta:
        abstract = True
    
    def calculate_checksum(self):
        """Generate integrity checksum for audit purposes"""
        data = f"{self.id}{self.created_at}{self.updated_at}{self.version}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def save(self, *args, **kwargs):
        if self.pk:
            self.version += 1
        self.checksum = self.calculate_checksum()
        super().save(*args, **kwargs)


class Bank(AuditableModel):
    """
    Bank entity with regulatory identifiers and compliance fields
    """
    BANK_TYPES = [
        ('COMMERCIAL', 'Commercial Bank'),
        ('INVESTMENT', 'Investment Bank'),
        ('CENTRAL', 'Central Bank'),
        ('COOPERATIVE', 'Cooperative Bank'),
        ('ISLAMIC', 'Islamic Bank'),
    ]
    
    name = models.CharField(max_length=255, db_index=True)
    legal_name = models.CharField(max_length=255)
    bank_code = models.CharField(max_length=20, unique=True, db_index=True)
    swift_code = models.CharField(max_length=11, unique=True, validators=[
        RegexValidator(r'^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$', 'Invalid SWIFT code format')
    ])
    routing_number = models.CharField(max_length=9, unique=True, validators=[
        RegexValidator(r'^\d{9}$', 'Routing number must be 9 digits')
    ])
    bank_type = models.CharField(max_length=20, choices=BANK_TYPES)
    regulatory_license = models.CharField(max_length=50, unique=True)
    established_date = models.DateField()
    headquarters_address = models.TextField()
    phone_number = PhoneNumberField(blank=True, null=True, region='RW')
    email = models.EmailField()
    website = models.URLField(blank=True)
    is_fdic_insured = models.BooleanField(default=True)
    insurance_amount = models.DecimalField(max_digits=15, decimal_places=2, default=250000.00)
    
    class Meta:
        indexes = [
            models.Index(fields=['bank_code', 'swift_code']),
            models.Index(fields=['bank_type', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.bank_code})"


class Branch(AuditableModel):
    """
    Bank branch with geographic and operational information
    """
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name='branches')
    branch_code = models.CharField(max_length=20, db_index=True)
    name = models.CharField(max_length=255)
    address = models.TextField()
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = CountryField(blank_label='(select country)', blank=True, null=True)
    phone_number = PhoneNumberField(blank=True, null=True, region='RW')
    email = models.EmailField()
    manager_name = models.CharField(max_length=255)
    opening_hours = models.JSONField(default=dict)
    services_offered = models.JSONField(default=list)
    is_main_branch = models.BooleanField(default=False)
    atm_available = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['bank', 'branch_code']
        indexes = [
            models.Index(fields=['bank', 'branch_code']),
            models.Index(fields=['city', 'state', 'country']),
        ]
    
    def __str__(self):
        return f"{self.bank.name} - {self.name}"
    


class CustomerProfile(AuditableModel):
    """
    Enhanced customer profile with compliance, KYC, and business relationship data.
    """

    # --- Constants ---
    CUSTOMER_TYPES = [
        ('INDIVIDUAL', 'Individual'),
        ('BUSINESS', 'Business'),
        ('CORPORATE', 'Corporate'),
        ('INSTITUTIONAL', 'Institutional'),
    ]

    RISK_LEVELS = [
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
        ('PROHIBITED', 'Prohibited'),
    ]

    KYC_STATUS = [
        ('PENDING', 'Pending Verification'),
        ('IN_PROGRESS', 'In Progress'),
        ('VERIFIED', 'Verified'),
        ('REJECTED', 'Rejected'),
        ('EXPIRED', 'Expired'),
    ]

    # --- Core Links ---
    customer = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer_profile')
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    profile_id = models.BigIntegerField(
        unique=True,
        db_index=True,
        validators=[
            MinValueValidator(Decimal('10000000')),
            MaxValueValidator(Decimal('9999999999'))
        ]
    )
    customer_type = models.CharField(max_length=20, choices=CUSTOMER_TYPES)

    # --- Personal Info ---
    date_of_birth = models.DateField(null=True, blank=True)
    ssn_encrypted = models.BinaryField(null=True, blank=True)  # Must be encrypted manually
    tax_id = models.CharField(max_length=20, blank=True)
    nationality = models.CharField(max_length=100)
    phone_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)

    # --- Contact Info ---
    phone_number = PhoneNumberField(blank=True, null=True)
    street_address = models.TextField()
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = CountryField(blank_label='(Select country)', blank=True, null=True)

    # --- Compliance ---
    kyc_status = models.CharField(max_length=20, choices=KYC_STATUS, default='PENDING')
    kyc_completed_date = models.DateTimeField(null=True, blank=True)
    kyc_expiry_date = models.DateTimeField(null=True, blank=True)
    risk_level = models.CharField(max_length=20, choices=RISK_LEVELS, default='MEDIUM')
    aml_check_status = models.BooleanField(default=False)
    aml_last_check = models.DateTimeField(null=True, blank=True)

    # --- Business Info (if applicable) ---
    business_name = models.CharField(max_length=255, blank=True)
    business_registration_number = models.CharField(max_length=50, blank=True)
    industry_code = models.CharField(max_length=10, blank=True)
    annual_income = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)

    # --- Banking Relationship ---
    primary_branch = models.ForeignKey(Branch, on_delete=models.SET_NULL, null=True, blank=True)
    relationship_manager = models.UUIDField(null=True, blank=True)  # Link to Employee/Staff if needed
    customer_since = models.DateTimeField(auto_now_add=True)

    # --- Metadata ---
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['customer_id', 'customer_type']),
            models.Index(fields=['kyc_status', 'risk_level']),
            models.Index(fields=['customer']),
        ]
        verbose_name = 'Customer Profile'
        verbose_name_plural = 'Customer Profiles'

    def __str__(self):
        return f"{self.customer.get_full_name() or self.customer.email} - {self.customer_id}"

    
    def encrypt_ssn(self, ssn, key):
        """Encrypt SSN using Fernet symmetric encryption"""
        f = Fernet(key)
        return f.encrypt(ssn.encode())
    
    def decrypt_ssn(self, key):
        """Decrypt SSN"""
        if self.ssn_encrypted:
            f = Fernet(key)
            return f.decrypt(self.ssn_encrypted).decode()
        return None
    
    def __str__(self):
        return f"{self.customer_id} - {self.get_full_name}"



class AccountType(AuditableModel):
    """
    Account type configuration with banking product specifications
    """
    ACCOUNT_CATEGORIES = [
        ('DEPOSIT', 'Deposit Account'),
        ('LOAN', 'Loan Account'),
        ('INVESTMENT', 'Investment Account'),
        ('CREDIT', 'Credit Account'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True)
    category = models.CharField(max_length=20, choices=ACCOUNT_CATEGORIES)
    description = models.TextField()
    
    # Interest and Fee Configuration
    interest_rate = models.DecimalField(max_digits=8, decimal_places=4, default=0)
    minimum_balance = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    maintenance_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    overdraft_limit = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    
    # Account Limits
    daily_withdrawal_limit = models.DecimalField(max_digits=15, decimal_places=2, null=True)
    monthly_transaction_limit = models.PositiveIntegerField(null=True)
    
    # Product Features
    allows_overdraft = models.BooleanField(default=False)
    requires_minimum_balance = models.BooleanField(default=True)
    compounds_interest = models.BooleanField(default=True)
    is_islamic_compliant = models.BooleanField(default=False)
    
    
    def __str__(self):
        return f"{self.name} ({self.code})"


class Account(AuditableModel):
    """
    Core account model with advanced security and audit features
    """
    ACCOUNT_STATUS = [
        ('PENDING', 'Pending Activation'),
        ('ACTIVE', 'Active'),
        ('FROZEN', 'Frozen'),
        ('DORMANT', 'Dormant'),
        ('CLOSED', 'Closed'),
        ('BLOCKED', 'Blocked'),
    ]
    
    account_number = models.BigIntegerField(
        unique=True, 
        db_index=True,
        validators=[MinValueValidator(Decimal('10000000')),  # Minimum 8 digits]
                    MaxValueValidator(Decimal('9999999999'))]  # Maximum 10 digits
    )
    customer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='accounts')
    account_type = models.ForeignKey(AccountType, on_delete=models.CASCADE)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE)
    
    # Balance and Status
    balance = models.DecimalField(
        max_digits=20, 
        decimal_places=2, 
        default=0,
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    available_balance = models.DecimalField(max_digits=20, decimal_places=2, default=0)
    hold_amount = models.DecimalField(max_digits=20, decimal_places=2, default=0)
    
    status = models.CharField(max_length=20, choices=ACCOUNT_STATUS, default='PENDING')
    
    # Account Dates
    opened_date = models.DateTimeField(auto_now_add=True)
    closed_date = models.DateTimeField(null=True, blank=True)
    last_transaction_date = models.DateTimeField(null=True, blank=True)
    last_statement_date = models.DateTimeField(null=True, blank=True)
    
    # Interest Calculation
    interest_accrued = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    last_interest_calculation = models.DateTimeField(null=True, blank=True)
    
    # Overdraft
    overdraft_limit = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    overdraft_used = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    
    # Compliance and Risk
    is_monitored = models.BooleanField(default=False)
    monitoring_reason = models.TextField(blank=True)
    risk_score = models.PositiveIntegerField(default=0)
    
    class Meta:
        indexes = [
            models.Index(fields=['customer', 'account_type']),
            models.Index(fields=['account_number', 'status']),
            models.Index(fields=['branch', 'status']),
            models.Index(fields=['is_monitored', 'risk_score']),
        ]
    
    def calculate_available_balance(self):
        """Calculate available balance considering holds and overdraft"""
        return self.balance - self.hold_amount + (self.overdraft_limit - self.overdraft_used)
    
    def can_debit(self, amount):
        """Check if account can be debited for the specified amount"""
        return self.calculate_available_balance() >= amount and self.status == 'ACTIVE'
    
    def __str__(self):
        return f"{self.account_number} - {self.customer.get_full_name}"


class Transaction(AuditableModel):
    """
    Immutable transaction model with double-entry bookkeeping principles
    """
    TRANSACTION_TYPES = [
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('TRANSFER', 'Transfer'),
        ('PAYMENT', 'Payment'),
        ('FEE', 'Fee'),
        ('INTEREST', 'Interest'),
        ('LOAN_DISBURSEMENT', 'Loan Disbursement'),
        ('LOAN_PAYMENT', 'Loan Payment'),
        ('REVERSAL', 'Reversal'),
        ('ADJUSTMENT', 'Adjustment'),
    ]
    
    TRANSACTION_STATUS = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
        ('REVERSED', 'Reversed'),
    ]
    
    CHANNELS = [
        ('BRANCH', 'Branch'),
        ('ATM', 'ATM'),
        ('ONLINE', 'Online Banking'),
        ('MOBILE', 'Mobile App'),
        ('PHONE', 'Phone Banking'),
        ('API', 'API'),
        ('SYSTEM', 'System Generated'),
    ]
    
    transaction_id = models.CharField(max_length=50, unique=True, db_index=True)
    reference_number = models.CharField(max_length=100, blank=True)
    
    # Account Information
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='transactions')
    counter_account = models.ForeignKey(Account, on_delete=models.CASCADE, null=True, blank=True, related_name='counter_transactions')
    
    # Transaction Details
    transaction_type = models.CharField(max_length=30, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=20, decimal_places=2, validators=[MinValueValidator(Decimal('0.01'))])
    currency = models.CharField(max_length=3, default='USD')
    description = models.TextField()
    
    # Balances (for audit trail)
    balance_before = models.DecimalField(max_digits=20, decimal_places=2)
    balance_after = models.DecimalField(max_digits=20, decimal_places=2)
    
    # Transaction Processing
    status = models.CharField(max_length=20, choices=TRANSACTION_STATUS, default='PENDING')
    channel = models.CharField(max_length=20, choices=CHANNELS)
    processed_by = models.UUIDField(null=True, blank=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    
    # Authorization and Security
    authorization_code = models.CharField(max_length=50, blank=True)
    is_authorized = models.BooleanField(default=False)
    authorized_by = models.UUIDField(null=True, blank=True)
    authorized_at = models.DateTimeField(null=True, blank=True)
    
    # External Integration
    external_reference = models.CharField(max_length=100, blank=True)
    batch_id = models.CharField(max_length=50, blank=True)
    
    # Fees and Charges
    fee_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Reversal Information
    original_transaction = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    reversal_reason = models.TextField(blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['transaction_id', 'status']),
            models.Index(fields=['account', 'created_at']),
            models.Index(fields=['transaction_type', 'created_at']),
            models.Index(fields=['status', 'processed_at']),
            models.Index(fields=['batch_id']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = self.generate_transaction_id()
        super().save(*args, **kwargs)
    
    def generate_transaction_id(self):
        """Generate unique transaction ID with timestamp and random component"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_part = uuid.uuid4().hex[:8].upper()
        return f"TXN{timestamp}{random_part}"
    
    def can_reverse(self):
        """Check if transaction can be reversed"""
        return (self.status == 'COMPLETED' and 
                not hasattr(self, 'reversal_transactions') and
                self.transaction_type not in ['REVERSAL', 'ADJUSTMENT'])
    
    def __str__(self):
        return f"{self.transaction_id} - {self.transaction_type} - ${self.amount}"


class Hold(AuditableModel):
    """
    Account holds for pending transactions and regulatory requirements
    """
    HOLD_TYPES = [
        ('AUTHORIZATION', 'Authorization Hold'),
        ('LEGAL', 'Legal Hold'),
        ('COMPLIANCE', 'Compliance Hold'),
        ('FRAUD', 'Fraud Prevention Hold'),
        ('MAINTENANCE', 'Maintenance Hold'),
    ]
    
    HOLD_STATUS = [
        ('ACTIVE', 'Active'),
        ('RELEASED', 'Released'),
        ('EXPIRED', 'Expired'),
    ]
    
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='holds')
    amount = models.DecimalField(max_digits=15, decimal_places=2, validators=[MinValueValidator(Decimal('0.01'))])
    hold_type = models.CharField(max_length=20, choices=HOLD_TYPES)
    status = models.CharField(max_length=20, choices=HOLD_STATUS, default='ACTIVE')
    
    reason = models.TextField()
    reference_number = models.CharField(max_length=100, blank=True)
    
    expires_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)
    released_by = models.UUIDField(null=True, blank=True)
    
    related_transaction = models.ForeignKey(Transaction, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        db_table = 'bank_holds'
        indexes = [
            models.Index(fields=['account', 'status']),
            models.Index(fields=['hold_type', 'status']),
            models.Index(fields=['expires_at']),
        ]
    
    def release_hold(self, released_by=None):
        """Release the hold and update account available balance"""
        with transaction.atomic():
            self.status = 'RELEASED'
            self.released_at = timezone.now()
            self.released_by = released_by
            self.save()
            
            # Update account hold amount
            self.account.hold_amount -= self.amount
            self.account.save(update_fields=['hold_amount'])
    
    def __str__(self):
        return f"Hold {self.amount} on {self.account.account_number}"


class AuditLog(models.Model):
    """
    Comprehensive audit logging for regulatory compliance
    """
    ACTION_TYPES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('TRANSACTION', 'Transaction'),
        ('AUTHORIZATION', 'Authorization'),
        ('ACCESS', 'Access'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    # User and Session Information
    user_id = models.UUIDField(null=True, blank=True, db_index=True)
    session_id = models.CharField(max_length=100, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Action Details
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    resource_type = models.CharField(max_length=100)  # Model name
    resource_id = models.CharField(max_length=100, blank=True)
    
    # Change Tracking
    old_values = models.JSONField(null=True, blank=True)
    new_values = models.JSONField(null=True, blank=True)
    
    # Additional Context
    description = models.TextField(blank=True)
    risk_level = models.CharField(max_length=20, default='LOW')
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp', 'action_type']),
            models.Index(fields=['user_id', 'timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['risk_level', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.action_type} - {self.resource_type} - {self.timestamp}"


class ComplianceAlert(AuditableModel):
    """
    Compliance monitoring and alert system
    """
    ALERT_TYPES = [
        ('AML', 'Anti-Money Laundering'),
        ('FRAUD', 'Fraud Detection'),
        ('SANCTIONS', 'Sanctions Screening'),
        ('LARGE_TRANSACTION', 'Large Transaction'),
        ('UNUSUAL_ACTIVITY', 'Unusual Activity'),
        ('DORMANT_ACCOUNT', 'Dormant Account'),
        ('KYC_EXPIRY', 'KYC Document Expiry'),
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Under Investigation'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
        ('ESCALATED', 'Escalated'),
    ]
    
    alert_id = models.CharField(max_length=50, unique=True, db_index=True)
    alert_type = models.CharField(max_length=30, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    
    # Related Entities
    customer = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, null=True, blank=True)
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, null=True, blank=True)
    
    # Alert Details
    title = models.CharField(max_length=255)
    description = models.TextField()
    details = models.JSONField(default=dict)
    
    # Investigation
    assigned_to = models.UUIDField(null=True, blank=True)
    assigned_at = models.DateTimeField(null=True, blank=True)
    investigated_by = models.UUIDField(null=True, blank=True)
    investigation_notes = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_summary = models.TextField(blank=True)
    
    # Regulatory Reporting
    reported_to_authorities = models.BooleanField(default=False)
    report_reference = models.CharField(max_length=100, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['alert_type', 'severity', 'status']),
            models.Index(fields=['customer', 'created_at']),
            models.Index(fields=['status', 'assigned_to']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.alert_id:
            self.alert_id = self.generate_alert_id()
        super().save(*args, **kwargs)
    
    def generate_alert_id(self):
        """Generate unique alert ID"""
        timestamp = datetime.now().strftime('%Y%m%d')
        random_part = uuid.uuid4().hex[:6].upper()
        return f"ALT{timestamp}{random_part}"
    
    def __str__(self):
        return f"{self.alert_id} - {self.alert_type} - {self.severity}"


# Custom Managers for enhanced query capabilities
class ActiveAccountManager(models.Manager):
    """Manager for active accounts only"""
    def get_queryset(self):
        return super().get_queryset().filter(status='ACTIVE', is_active=True)


class TransactionManager(models.Manager):
    """Enhanced transaction manager with common queries"""
    
    @property
    def completed(self):
        return self.filter(status='COMPLETED')
    
    @property
    def pending(self):
        return self.filter(status='PENDING')
    
    def by_account(self, account):
        return self.filter(account=account).order_by('-created_at')
    
    def by_date_range(self, start_date, end_date):
        return self.filter(created_at__range=[start_date, end_date])


# Add custom managers to models
Account.active_accounts = ActiveAccountManager()
Transaction.objects = TransactionManager()


# Database constraints and triggers would be implemented at the database level
# for additional data integrity in production environments