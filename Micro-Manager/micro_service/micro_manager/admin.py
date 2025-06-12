from django.contrib import admin
from django.utils.html import format_html
from .models import ServiceAccount

@admin.register(ServiceAccount)
class ServiceAccountAdmin(admin.ModelAdmin):
    list_display = (
        'name', 
        'service_type', 
        'is_active', 
        'registered_at', 
        'updated_at',
        'last_login',
        'api_key_display',
    )
    list_filter = ('service_type', 'is_active')
    search_fields = ('name', 'api_key')
    ordering = ('-registered_at',)

    readonly_fields = ('registered_at', 'updated_at', 'last_login')

    fieldsets = (
        (None, {'fields': ('name', 'password')}),
        ('Service Info', {'fields': ('service_type', 'api_key',)}),
        ('Status', {'fields': ('is_active',)}),
        ('Timestamps', {'fields': ('registered_at', 'updated_at', 'last_login')}),
    )

    def api_key_display(self, obj):
        if obj.api_key:
            return format_html("<code>{}</code>", obj.api_key[:8] + "..." if len(obj.api_key) > 8 else obj.api_key)
        return "-"
    api_key_display.short_description = "API Key"
