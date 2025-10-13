from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from .models import Tenant, User, Invite


# -----------------------------
#  Tenant Admin
# -----------------------------
@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'domain', 'created_at', 'user_count')
    search_fields = ('name', 'slug', 'domain')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)
    
    def user_count(self, obj):
        return obj.users.count()
    user_count.short_description = "Users"

    fieldsets = (
        (None, {'fields': ('name', 'slug', 'domain')}),
        ('Metadata', {'fields': ('created_at',)}),
    )


# -----------------------------
#  Custom User Admin
# -----------------------------
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    # Display
    list_display = ('username', 'email', 'tenant', 'role', 'is_active', 'date_joined')
    list_filter = ('tenant', 'role', 'is_active')
    search_fields = ('username', 'email')
    ordering = ('-date_joined',)
    readonly_fields = ('date_joined',)

    # Field organization
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        (_('Tenant & Role'), {'fields': ('tenant', 'role')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Timestamps'), {'fields': ('date_joined',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'tenant', 'role', 'password1', 'password2'),
        }),
    )

    def get_queryset(self, request):
        """
        Optionally limit visibility: 
        Superusers see all, others only their tenant’s users.
        """
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if getattr(request.user, 'tenant', None):
            return qs.filter(tenant=request.user.tenant)
        return qs.none()


# -----------------------------
#  Invite Admin
# -----------------------------
@admin.register(Invite)
class InviteAdmin(admin.ModelAdmin):
    list_display = ('email', 'tenant', 'role', 'accepted', 'expires_at', 'is_valid_colored')
    list_filter = ('tenant', 'role', 'accepted')
    search_fields = ('email', 'tenant__slug', 'token')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'expires_at', 'token', 'accepted')

    fieldsets = (
        (None, {'fields': ('tenant', 'email', 'role')}),
        ('Token Info', {'fields': ('token', 'accepted', 'expires_at', 'created_at')}),
    )

    def is_valid_colored(self, obj):
        if obj.is_valid():
            color = "green"
            text = "Valid"
        else:
            color = "red"
            text = "Expired"
        return format_html(f'<b style="color:{color}">{text}</b>')
    is_valid_colored.short_description = "Status"

    def get_queryset(self, request):
        """
        Limit invites to current tenant for non-superusers.
        """
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        if getattr(request.user, 'tenant', None):
            return qs.filter(tenant=request.user.tenant)
        return qs.none()
