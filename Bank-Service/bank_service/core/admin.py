"""
Professional Bank System Django Admin Configuration
Enterprise-grade admin interface with advanced security, audit trails,
user experience optimization, and operational efficiency features.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.admin import SimpleListFilter
from django.urls import reverse
from django.utils.html import format_html, mark_safe
from django.utils.safestring import mark_safe
from django.db.models import Sum, Count, Q
from django.http import HttpResponse
from django.shortcuts import render
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.utils import timezone
from datetime import datetime, timedelta
import csv
import json
from decimal import Decimal
from .models import (
    Bank, Branch, CustomerProfile,
    AccountType, Account, Transaction, 
    Hold, AuditLog, ComplianceAlert
) 

class AuditableMixin:
    """
    Mixin for auditable admin interfaces with enhanced security logging
    """
    def save_model(self, request, obj, form, change):
        # Capture user information for audit trail
        if hasattr(obj, 'created_by') and not change:
            obj.created_by = request.user.id
        if hasattr(obj, 'updated_by'):
            obj.updated_by = request.user.id
        
        # Log the admin action
        action_type = 'UPDATE' if change else 'CREATE'
        AuditLog.objects.create(
            user_id=request.user.id,
            session_id=request.session.session_key,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            action_type=action_type,
            resource_type=obj.__class__.__name__,
            resource_id=str(obj.pk),
            description=f"Admin {action_type.lower()} operation",
            risk_level='MEDIUM' if obj.__class__.__name__ in ['Account', 'Transaction'] else 'LOW'
        )
        
        super().save_model(request, obj, form, change)
    
    def get_client_ip(self, request):
        """Extract client IP address with proxy consideration"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ReadOnlyMixin:
    """
    Mixin for read-only admin interfaces for sensitive financial data
    """
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return request.user.has_perm('view_readonly_financial_data')
    
    def has_delete_permission(self, request, obj=None):
        return False


class ExportMixin:
    """
    Mixin for CSV export functionality with audit logging
    """
    def export_as_csv(self, request, queryset):
        """Export selected items as CSV with audit trail"""
        meta = self.model._meta
        field_names = [field.name for field in meta.fields]
        
        # Log export action
        AuditLog.objects.create(
            user_id=request.user.id,
            session_id=request.session.session_key,
            ip_address=request.META.get('REMOTE_ADDR'),
            action_type='ACCESS',
            resource_type=meta.model_name,
            description=f"CSV export of {queryset.count()} records",
            risk_level='HIGH'
        )
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename={meta.model_name}_export.csv'
        writer = csv.writer(response)
        
        writer.writerow(field_names)
        for obj in queryset:
            writer.writerow([getattr(obj, field) for field in field_names])
        
        return response
    
    export_as_csv.short_description = "Export Selected as CSV"


# Custom Filters
class RiskLevelFilter(SimpleListFilter):
    title = 'Risk Level'
    parameter_name = 'risk_level'
    
    def lookups(self, request, model_admin):
        return [
            ('low', 'Low Risk'),
            ('medium', 'Medium Risk'),
            ('high', 'High Risk'),
            ('critical', 'Critical Risk'),
        ]
    
    def queryset(self, request, queryset):
        if self.value() == 'low':
            return queryset.filter(risk_level='LOW')
        elif self.value() == 'medium':
            return queryset.filter(risk_level='MEDIUM')
        elif self.value() == 'high':
            return queryset.filter(risk_level='HIGH')
        elif self.value() == 'critical':
            return queryset.filter(risk_score__gte=80)
        return queryset


class TransactionAmountFilter(SimpleListFilter):
    title = 'Transaction Amount'
    parameter_name = 'amount_range'
    
    def lookups(self, request, model_admin):
        return [
            ('small', 'Under $1,000'),
            ('medium', '$1,000 - $10,000'),
            ('large', '$10,000 - $100,000'),
            ('very_large', 'Over $100,000'),
        ]
    
    def queryset(self, request, queryset):
        if self.value() == 'small':
            return queryset.filter(amount__lt=1000)
        elif self.value() == 'medium':
            return queryset.filter(amount__gte=1000, amount__lt=10000)
        elif self.value() == 'large':
            return queryset.filter(amount__gte=10000, amount__lt=100000)
        elif self.value() == 'very_large':
            return queryset.filter(amount__gte=100000)
        return queryset


class RecentActivityFilter(SimpleListFilter):
    title = 'Recent Activity'
    parameter_name = 'recent_activity'
    
    def lookups(self, request, model_admin):
        return [
            ('today', 'Today'),
            ('week', 'This Week'),
            ('month', 'This Month'),
            ('quarter', 'This Quarter'),
        ]
    
    def queryset(self, request, queryset):
        now = timezone.now()
        if self.value() == 'today':
            return queryset.filter(created_at__date=now.date())
        elif self.value() == 'week':
            week_ago = now - timedelta(days=7)
            return queryset.filter(created_at__gte=week_ago)
        elif self.value() == 'month':
            month_ago = now - timedelta(days=30)
            return queryset.filter(created_at__gte=month_ago)
        elif self.value() == 'quarter':
            quarter_ago = now - timedelta(days=90)
            return queryset.filter(created_at__gte=quarter_ago)
        return queryset


# Inline Admin Classes
class BranchInline(admin.TabularInline):
    model = Branch
    extra = 0
    fields = ('branch_code', 'name', 'city', 'state', 'phone', 'is_main_branch', 'is_active')
    readonly_fields = ('created_at', 'updated_at')


# class AccountInline(admin.TabularInline):
#     model = Account
#     extra = 0
#     fields = ('account_number', 'account_type', 'balance', 'status', 'is_active')
#     readonly_fields = ('account_number', 'balance', 'created_at')
#     max_num = 5  # Limit display for performance

class TransactionInline(admin.TabularInline):
    model = Transaction
    fk_name = 'account'  # Specify the correct ForeignKey field name here
    extra = 0
    fields = ('transaction_id', 'transaction_type', 'amount', 'status', 'created_at')
    readonly_fields = ('transaction_id', 'amount', 'status', 'created_at')
    max_num = 10  # Performance optimization
    ordering = ('-created_at',)




class HoldInline(admin.TabularInline):
    model = Hold
    extra = 0
    fields = ('amount', 'hold_type', 'status', 'reason', 'expires_at')
    readonly_fields = ('created_at',)


# Main Admin Classes
@admin.register(Bank)
class BankAdmin(admin.ModelAdmin, AuditableMixin, ExportMixin):
    list_display = (
        'name', 'bank_code', 'swift_code', 'bank_type', 
        'is_fdic_insured', 'branch_count', 'is_active'
    )
    list_filter = ('bank_type', 'is_fdic_insured', 'is_active', 'created_at')
    search_fields = ('name', 'legal_name', 'bank_code', 'swift_code')
    readonly_fields = ('id', 'created_at', 'updated_at', 'checksum', 'version')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'legal_name', 'bank_type')
        }),
        ('Banking Identifiers', {
            'fields': ('bank_code', 'swift_code', 'routing_number')
        }),
        ('Regulatory Information', {
            'fields': ('regulatory_license', 'established_date', 'is_fdic_insured', 'insurance_amount')
        }),
        ('Contact Information', {
            'fields': ('headquarters_address', 'phone', 'email', 'website')
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at', 'version', 'checksum', 'is_active'),
            'classes': ('collapse',)
        })
    )
    
    inlines = [BranchInline]
    actions = ['export_as_csv', 'activate_banks', 'deactivate_banks']
    
    def branch_count(self, obj):
        return obj.branches.filter(is_active=True).count()
    branch_count.short_description = 'Active Branches'
    
    def activate_banks(self, request, queryset):
        updated = queryset.update(is_active=True)
        messages.success(request, f'{updated} banks activated successfully.')
    activate_banks.short_description = 'Activate selected banks'
    
    def deactivate_banks(self, request, queryset):
        updated = queryset.update(is_active=False)
        messages.success(request, f'{updated} banks deactivated successfully.')
    deactivate_banks.short_description = 'Deactivate selected banks'


@admin.register(Branch)
class BranchAdmin(admin.ModelAdmin, AuditableMixin, ExportMixin):
    list_display = (
        'name', 'bank', 'branch_code', 'city', 'state', 
        'manager_name', 'is_main_branch', 'atm_available', 'is_active'
    )
    list_filter = ('bank', 'is_main_branch', 'atm_available', 'country', 'is_active')
    search_fields = ('name', 'branch_code', 'city', 'manager_name')
    readonly_fields = ('id', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Branch Information', {
            'fields': ('bank', 'branch_code', 'name', 'manager_name')
        }),
        ('Location', {
            'fields': ('address', 'city', 'state', 'postal_code', 'country')
        }),
        ('Contact & Services', {
            'fields': ('phone', 'email', 'opening_hours', 'services_offered')
        }),
        ('Features', {
            'fields': ('is_main_branch', 'atm_available', 'is_active')
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    actions = ['export_as_csv']


@admin.register(CustomerProfile)
class CustomerProfileAdmin(admin.ModelAdmin, AuditableMixin, ExportMixin):
    list_display = (
        'profile_id', 'customer_type', 'kyc_status', 'risk_level', 
        'business_name', 'customer_since', 'get_email', 'get_full_name'
    )
    list_filter = (
        'customer_type', 'kyc_status', 'risk_level', 
        'email_verified', 'phone_verified'
    )
    search_fields = ('profile_id', 'business_name', 'customer__email', 'customer__first_name', 'customer__last_name')
    readonly_fields = ('id', 'profile_id', 'customer_since', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Core Links', {
            'fields': ('customer', 'profile_id', 'customer_type')
        }),
        ('Personal Information', {
            'fields': (
                'date_of_birth', 'nationality', 'phone_number', 'phone_verified', 'email_verified'
            )
        }),
        ('Address', {
            'fields': ('street_address', 'city', 'state', 'postal_code', 'country')
        }),
        ('Business Information', {
            'fields': ('business_name', 'business_registration_number', 'industry_code', 'annual_income'),
            'classes': ('collapse',)
        }),
        ('KYC & Compliance', {
            'fields': (
                'kyc_status', 'kyc_completed_date', 'kyc_expiry_date',
                'risk_level', 'aml_check_status', 'aml_last_check'
            )
        }),
        ('Banking Relationship', {
            'fields': ('primary_branch', 'relationship_manager', 'customer_since')
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    # inlines = [AccountInline]
    actions = ['export_as_csv', 'mark_high_risk', 'verify_kyc']
    
    def get_email(self, obj):
        return obj.customer.email
    get_email.short_description = 'Email'

    def get_full_name(self, obj):
        return obj.customer.get_full_name()
    get_full_name.short_description = 'Full Name'
    
    
    
    def account_count(self, obj):
        return obj.accounts.filter(is_active=True).count()
    account_count.short_description = 'Active Accounts'
    
    def mark_high_risk(self, request, queryset):
        updated = queryset.update(risk_level='HIGH')
        messages.warning(request, f'{updated} customers marked as high risk.')
    mark_high_risk.short_description = 'Mark as High Risk'
    
    def verify_kyc(self, request, queryset):
        updated = queryset.update(kyc_status='VERIFIED', kyc_completed_date=timezone.now())
        messages.success(request, f'{updated} customers KYC verified.')
    verify_kyc.short_description = 'Verify KYC Status'


@admin.register(AccountType)
class AccountTypeAdmin(admin.ModelAdmin, AuditableMixin):
    list_display = (
        'name', 'code', 'category', 'interest_rate', 
        'minimum_balance', 'maintenance_fee', 'is_active'
    )
    list_filter = ('category', 'allows_overdraft', 'requires_minimum_balance', 'is_islamic_compliant')
    search_fields = ('name', 'code', 'description')
    readonly_fields = ('id', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Product Information', {
            'fields': ('name', 'code', 'category', 'description')
        }),
        ('Financial Configuration', {
            'fields': (
                'interest_rate', 'minimum_balance', 'maintenance_fee', 'overdraft_limit'
            )
        }),
        ('Limits & Features', {
            'fields': (
                'daily_withdrawal_limit', 'monthly_transaction_limit',
                'allows_overdraft', 'requires_minimum_balance', 
                'compounds_interest', 'is_islamic_compliant'
            )
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at', 'is_active'),
            'classes': ('collapse',)
        })
    )


@admin.register(Account)
class AccountAdmin(admin.ModelAdmin, AuditableMixin, ExportMixin):
    list_display = (
        'account_number', 'customer_link', 'account_type', 'balance_display', 
        'available_balance_display', 'status', 'risk_indicator', 'last_transaction_date'
    )
    list_filter = (
        'account_type', 'status', 'branch', 'is_monitored', 
        RiskLevelFilter, RecentActivityFilter
    )
    search_fields = ('account_number', 'customer__customer_id', 'customer__first_name', 'customer__last_name')
    readonly_fields = (
        'id', 'account_number', 'balance', 'available_balance', 'hold_amount',
        'interest_accrued', 'created_at', 'updated_at', 'last_transaction_date'
    )
    
    fieldsets = (
        ('Account Information', {
            'fields': ('account_number', 'customer', 'account_type', 'branch')
        }),
        ('Balance Information', {
            'fields': (
                'balance', 'available_balance', 'hold_amount', 
                'interest_accrued', 'last_interest_calculation'
            )
        }),
        ('Overdraft', {
            'fields': ('overdraft_limit', 'overdraft_used'),
            'classes': ('collapse',)
        }),
        ('Status & Monitoring', {
            'fields': (
                'status', 'is_monitored', 'monitoring_reason', 'risk_score'
            )
        }),
        ('Dates', {
            'fields': (
                'opened_date', 'closed_date', 'last_transaction_date', 'last_statement_date'
            )
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at', 'is_active'),
            'classes': ('collapse',)
        })
    )
    
    inlines = [TransactionInline, HoldInline]
    actions = ['export_as_csv', 'freeze_accounts', 'unfreeze_accounts', 'flag_for_monitoring']
    
    def customer_link(self, obj):
        url = reverse('admin:yourapp_customer_change', args=[obj.customer.pk])
        return format_html('<a href="{}">{}</a>', url, obj.customer.get_full_name())
    customer_link.short_description = 'Customer'
    customer_link.admin_order_field = 'customer__first_name'
    
    def balance_display(self, obj):
        color = 'red' if obj.balance < 0 else 'green'
        return format_html('<span style="color: {};">${:,.2f}</span>', color, obj.balance)
    balance_display.short_description = 'Balance'
    balance_display.admin_order_field = 'balance'
    
    def available_balance_display(self, obj):
        available = obj.calculate_available_balance()
        color = 'red' if available < 0 else 'green'
        return format_html('<span style="color: {};">${:,.2f}</span>', color, available)
    available_balance_display.short_description = 'Available Balance'
    
    def risk_indicator(self, obj):
        if obj.risk_score >= 80:
            return format_html('<span style="color: red;">⚠️ HIGH</span>')
        elif obj.risk_score >= 50:
            return format_html('<span style="color: orange;">⚠️ MEDIUM</span>')
        return format_html('<span style="color: green;">✓ LOW</span>')
    risk_indicator.short_description = 'Risk'
    
    def freeze_accounts(self, request, queryset):
        updated = queryset.update(status='FROZEN')
        messages.warning(request, f'{updated} accounts frozen.')
    freeze_accounts.short_description = 'Freeze Selected Accounts'
    
    def unfreeze_accounts(self, request, queryset):
        updated = queryset.filter(status='FROZEN').update(status='ACTIVE')
        messages.success(request, f'{updated} accounts unfrozen.')
    unfreeze_accounts.short_description = 'Unfreeze Selected Accounts'
    
    def flag_for_monitoring(self, request, queryset):
        updated = queryset.update(is_monitored=True, monitoring_reason='Admin flagged for review')
        messages.info(request, f'{updated} accounts flagged for monitoring.')
    flag_for_monitoring.short_description = 'Flag for Monitoring'


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin, ReadOnlyMixin, ExportMixin):
    list_display = (
        'transaction_id', 'account_link', 'transaction_type', 'amount_display',
        'status', 'channel', 'created_at', 'authorization_status'
    )
    list_filter = (
        'transaction_type', 'status', 'channel', 'currency',
        TransactionAmountFilter, RecentActivityFilter
    )
    search_fields = (
        'transaction_id', 'reference_number', 'account__account_number',
        'account__customer__customer_id', 'description'
    )
    readonly_fields = (
        'id', 'transaction_id', 'balance_before', 'balance_after',
        'created_at', 'updated_at', 'processed_at', 'authorized_at'
    )
    
    fieldsets = (
        ('Transaction Information', {
            'fields': (
                'transaction_id', 'reference_number', 'transaction_type',
                'amount', 'currency', 'description'
            )
        }),
        ('Accounts', {
            'fields': ('account', 'counter_account')
        }),
        ('Balance Information', {
            'fields': ('balance_before', 'balance_after'),
            'classes': ('collapse',)
        }),
        ('Processing', {
            'fields': (
                'status', 'channel', 'processed_by', 'processed_at'
            )
        }),
        ('Authorization', {
            'fields': (
                'authorization_code', 'is_authorized', 'authorized_by', 'authorized_at'
            ),
            'classes': ('collapse',)
        }),
        ('Fees & External', {
            'fields': (
                'fee_amount', 'tax_amount', 'external_reference', 'batch_id'
            ),
            'classes': ('collapse',)
        }),
        ('Reversal Information', {
            'fields': ('original_transaction', 'reversal_reason'),
            'classes': ('collapse',)
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    actions = ['export_as_csv']
    date_hierarchy = 'created_at'
    
    def account_link(self, obj):
        url = reverse('admin:yourapp_account_change', args=[obj.account.pk])
        return format_html('<a href="{}">{}</a>', url, obj.account.account_number)
    account_link.short_description = 'Account'
    
    def amount_display(self, obj):
        color = 'green' if obj.transaction_type in ['DEPOSIT', 'INTEREST'] else 'red'
        return format_html('<span style="color: {};">${:,.2f}</span>', color, obj.amount)
    amount_display.short_description = 'Amount'
    amount_display.admin_order_field = 'amount'
    
    def authorization_status(self, obj):
        if obj.is_authorized:
            return format_html('<span style="color: green;">✓ Authorized</span>')
        return format_html('<span style="color: red;">✗ Not Authorized</span>')
    authorization_status.short_description = 'Auth Status'


@admin.register(Hold)
class HoldAdmin(admin.ModelAdmin, AuditableMixin, ExportMixin):
    list_display = (
        'account_link', 'amount_display', 'hold_type', 'status',
        'created_at', 'expires_at', 'days_remaining'
    )
    list_filter = ('hold_type', 'status', 'created_at', 'expires_at')
    search_fields = ('account__account_number', 'reason', 'reference_number')
    readonly_fields = ('id', 'created_at', 'updated_at', 'released_at')
    
    fieldsets = (
        ('Hold Information', {
            'fields': ('account', 'amount', 'hold_type', 'status')
        }),
        ('Details', {
            'fields': ('reason', 'reference_number', 'related_transaction')
        }),
        ('Timing', {
            'fields': ('expires_at', 'released_at', 'released_by')
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    actions = ['export_as_csv', 'release_holds', 'extend_holds']
    
    def account_link(self, obj):
        url = reverse('admin:yourapp_account_change', args=[obj.account.pk])
        return format_html('<a href="{}">{}</a>', url, obj.account.account_number)
    account_link.short_description = 'Account'
    
    def amount_display(self, obj):
        return format_html('<span style="color: orange;">${:,.2f}</span>', obj.amount)
    amount_display.short_description = 'Hold Amount'
    amount_display.admin_order_field = 'amount'
    
    def days_remaining(self, obj):
        if obj.expires_at and obj.status == 'ACTIVE':
            days = (obj.expires_at.date() - timezone.now().date()).days
            color = 'red' if days <= 1 else 'orange' if days <= 7 else 'green'
            return format_html('<span style="color: {};">{} days</span>', color, days)
        return '-'
    days_remaining.short_description = 'Days Remaining'
    
    def release_holds(self, request, queryset):
        count = 0
        for hold in queryset.filter(status='ACTIVE'):
            hold.release_hold(released_by=request.user.id)
            count += 1
        messages.success(request, f'{count} holds released.')
    release_holds.short_description = 'Release Selected Holds'
    
    def extend_holds(self, request, queryset):
        future_date = timezone.now() + timedelta(days=30)
        updated = queryset.filter(status='ACTIVE').update(expires_at=future_date)
        messages.info(request, f'{updated} holds extended by 30 days.')
    extend_holds.short_description = 'Extend Holds by 30 Days'


@admin.register(ComplianceAlert)
class ComplianceAlertAdmin(admin.ModelAdmin, AuditableMixin, ExportMixin):
    list_display = (
        'alert_id', 'alert_type', 'severity_display', 'customer_link',
        'status', 'assigned_to_display', 'created_at'
    )
    list_filter = (
        'alert_type', 'severity', 'status', 'reported_to_authorities',
        RecentActivityFilter
    )
    search_fields = (
        'alert_id', 'title', 'customer__customer_id',
        'customer__first_name', 'customer__last_name'
    )
    readonly_fields = (
        'id', 'alert_id', 'created_at', 'updated_at',
        'assigned_at', 'resolved_at'
    )
    
    fieldsets = (
        ('Alert Information', {
            'fields': ('alert_id', 'alert_type', 'severity', 'status', 'title')
        }),
        ('Related Entities', {
            'fields': ('customer', 'account', 'transaction')
        }),
        ('Details', {
            'fields': ('description', 'details')
        }),
        ('Investigation', {
            'fields': (
                'assigned_to', 'assigned_at', 'investigated_by',
                'investigation_notes', 'resolved_at', 'resolution_summary'
            ),
            'classes': ('collapse',)
        }),
        ('Regulatory Reporting', {
            'fields': ('reported_to_authorities', 'report_reference'),
            'classes': ('collapse',)
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    actions = ['export_as_csv', 'assign_to_me', 'mark_resolved', 'escalate_alerts']
    
    def severity_display(self, obj):
        colors = {
            'LOW': 'green',
            'MEDIUM': 'orange', 
            'HIGH': 'red',
            'CRITICAL': 'darkred'
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.severity, 'black'), obj.severity
        )
    severity_display.short_description = 'Severity'
    severity_display.admin_order_field = 'severity'
    
    def customer_link(self, obj):
        if obj.customer:
            url = reverse('admin:yourapp_customer_change', args=[obj.customer.pk])
            return format_html('<a href="{}">{}</a>', url, obj.customer.get_full_name())
        return '-'
    customer_link.short_description = 'Customer'
    
    def assigned_to_display(self, obj):
        if obj.assigned_to:
            return f"User {obj.assigned_to}"
        return format_html('<span style="color: red;">Unassigned</span>')
    assigned_to_display.short_description = 'Assigned To'
    
    def assign_to_me(self, request, queryset):
        updated = queryset.filter(status='OPEN').update(
            assigned_to=request.user.id,
            assigned_at=timezone.now(),
            status='INVESTIGATING'
        )
        messages.success(request, f'{updated} alerts assigned to you.')
    assign_to_me.short_description = 'Assign to Me'