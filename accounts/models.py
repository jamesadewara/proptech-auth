import random
import secrets
import uuid
from datetime import timedelta
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.checks import register, Warning
from django.conf import settings
from django.core.validators import RegexValidator

INVITE_EXPIRY_HOURS = settings.INVITE_EXPIRY_HOURS or ""

# username validator: allow common username chars including leading @
USERNAME_REGEX = r'^[A-Za-z0-9_@.\-]+$'
username_validator = RegexValidator(
    regex=USERNAME_REGEX,
    message="Username may contain letters, numbers, underscores, dots, hyphens, and '@'."
)

class Tenant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=80, unique=True, help_text="Unique slug e.g. 'goldenstate'")
    domain = models.SlugField(max_length=80, unique=True, null=True, blank=True, help_text="Optional subdomain")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.slug

class UserManager(BaseUserManager):
    def create_user(self, email, username=None, password=None, tenant=None, role='GUEST', **extra_fields):
        if not email:
            raise ValueError("Email required")
        email = self.normalize_email(email)
        if username:
            username = username if username.startswith('@') else f"@{username}"
        else:
            username = f"@{email.split('@')[0]}"
        user = self.model(email=email.lower(), username=username.lower(), tenant=tenant, role=role, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username=None, password=None, **extra_fields):
        user = self.create_user(email=email, username=username, password=password, **extra_fields)
        user.is_staff = True
        user.is_active = True
        user.is_superuser = True
        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('OWNER','Owner'),
        ('STAFF','Staff'),
        ('AGENT','Agent'),
        ('GUEST','Guest'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, related_name='users', on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField()
    username = models.CharField(max_length=50, validators=[username_validator], unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='GUEST')
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    is_active = models.BooleanField(default=True)  # require email verification
    is_staff = models.BooleanField(default=False)  # site admin (not tenant owner)
    date_joined = models.DateTimeField(auto_now_add=True)
    email_verified = models.BooleanField(default=False)
    email_otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        unique_together = ("tenant", "email")
        constraints = [
            models.UniqueConstraint(fields=['tenant', 'email'], name='unique_tenant_email'),
            models.UniqueConstraint(fields=['tenant', 'username'], name='unique_tenant_username'),
        ]
        indexes = [
            models.Index(fields=['tenant', 'email']),
            models.Index(fields=['tenant', 'username']),
        ]

    def __str__(self):
        return f"{self.username} ({self.email})"
    
    def generate_otp(self):
        """Generate a 6-digit OTP valid for 10 minutes."""
        self.email_otp = str(random.randint(100000, 999999))
        self.otp_expiry = timezone.now() + timedelta(minutes=10)
        self.save(update_fields=['email_otp', 'otp_expiry'])
        return self.email_otp

    def verify_otp(self, otp):
        """Verify OTP and clear it if valid."""
        if (
            self.email_otp == otp
            and self.otp_expiry
            and timezone.now() < self.otp_expiry
        ):
            self.email_verified = True
            self.email_otp = None
            self.otp_expiry = None
            self.save(update_fields=['email_verified', 'email_otp', 'otp_expiry'])
            return True
        return False

class Invite(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, related_name='invites', on_delete=models.CASCADE)
    email = models.EmailField()
    role = models.CharField(max_length=20, choices=User.ROLE_CHOICES, default='STAFF')
    token = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    accepted = models.BooleanField(default=False)

    class Meta:
        unique_together = ('tenant', 'email')
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=int(INVITE_EXPIRY_HOURS))
        return super().save(*args, **kwargs)

    def is_valid(self):
        return (not self.accepted) and (timezone.now() < self.expires_at)

    def __str__(self):
        return f"Invite {self.email} -> {self.tenant.slug} ({self.role})"

@register()
def ignore_auth_warning(app_configs, **kwargs):
    return [
        Warning(
            "Ignoring W004: Multi-tenant system handles unique emails per tenant.",
            hint="Tenant-based authentication backend in use.",
            id="auth.W004",
        ),
    ]

class PasswordResetToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=30)  # 30 minutes default
        return super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() < self.expires_at