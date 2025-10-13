from django.contrib.auth import authenticate
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import PasswordResetToken, Tenant, Invite
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer as BaseTokenObtainPairSerializer
from datetime import timedelta
from django.utils import timezone
from django.conf import settings 
from rest_framework import generics, permissions, status, serializers as drf_serializers

User = get_user_model()
INVITE_EXPIRY_HOURS = settings.INVITE_EXPIRY_HOURS or ""

class RegisterTenantSerializer(serializers.Serializer):
    name = serializers.CharField()
    slug = serializers.SlugField()
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate_slug(self, value):
        if Tenant.objects.filter(slug=value).exists():
            raise serializers.ValidationError("Tenant slug already exists.")
        return value

    def create(self, validated_data):
        tenant = Tenant.objects.create(name=validated_data['name'], slug=validated_data['slug'])
        owner = User.objects.create_user(email=validated_data['email'],username=f"@{validated_data['email'].split('@')[0]}", password=validated_data['password'], tenant=tenant, role='OWNER')
        # owner is not is_staff sitewide; tenant owner role controls tenant actions
        return owner
    
# --- Tenant-aware login using tenant from middleware/header ---
class TenantTokenObtainPairSerializer(BaseTokenObtainPairSerializer):
    """
    Validate credentials against tenant attached to request (via middleware or header).
    """
    def validate(self, attrs):
        request = self.context.get('request')
        username = attrs.get(self.username_field)
        password = attrs.get('password')
        tenant = getattr(request, 'tenant', None)
        user = authenticate(request=request, username=username, password=password, tenant=tenant)
        if user is None:
            # use DRF serializer ValidationError so DRF will return status 400 with details
            raise drf_serializers.ValidationError("No active account found for given credentials and tenant.")
        # set the authenticated user so the parent serializer uses it
        self.user = user
        data = super().validate(attrs)  # this will generate tokens for self.user
        data['user_id'] = str(user.id)
        data['tenant'] = user.tenant.slug if user.tenant else None
        data['role'] = user.role
        return data
    
class InviteCreateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)

    def validate_email(self, value):
        request = self.context.get('request')
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            raise serializers.ValidationError("Tenant cannot be resolved.")
        if User.objects.filter(email__iexact=value, tenant=tenant).exists():
            raise serializers.ValidationError("User with this email already exists for this tenant.")
        return value

    def create(self, validated_data):
        import secrets
        request = self.context.get('request')
        tenant = request.tenant
        email = validated_data['email']
        role = validated_data['role']

        # Check if invite already exists for same tenant + email
        existing_invite = Invite.objects.filter(tenant=tenant, email=email).first()

        if existing_invite:
            if existing_invite.accepted:
                raise serializers.ValidationError("This invite has already been accepted.")
            # Refresh token and expiration for resend
            existing_invite.token = secrets.token_urlsafe(32)
            existing_invite.expires_at = timezone.now() + timedelta(hours=int(INVITE_EXPIRY_HOURS))
            existing_invite.save()
            return existing_invite

        # Otherwise create new invite
        token = secrets.token_urlsafe(32)
        invite = Invite.objects.create(
            tenant=tenant,
            email=email,
            role=role,
            token=token
        )
        return invite

    
class InviteAcceptSerializer(serializers.Serializer):
    token = serializers.CharField()
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, min_length=6)

    def validate(self, attrs):
        try:
            invite = Invite.objects.get(token=attrs['token'])
        except Invite.DoesNotExist:
            raise serializers.ValidationError("Invalid invite token.")
        if not invite.is_valid():
            raise serializers.ValidationError("Invite expired or already used.")
        attrs['invite'] = invite
        return attrs

    def create(self, validated_data):
        invite = validated_data['invite']
        username = validated_data['username']
        if not username.startswith('@'):
            username = f"@{username}"

        password = validated_data['password']
        user = User.objects.create_user(
            email=invite.email,
            username=username,
            password=password,
            tenant=invite.tenant,
            role=invite.role
        )
        invite.accepted = True
        invite.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    tenant = serializers.SlugRelatedField(read_only=True, slug_field='slug')

    class Meta:
        model = User
        fields = ('id','email','username','role','tenant')
        read_only_fields = ('id','tenant','role')

class PasswordForgotSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        request = self.context.get('request')
        tenant = getattr(request, 'tenant', None)

        if tenant:
            qs = User.objects.filter(email__iexact=value, tenant=tenant)
        else:
            qs = User.objects.filter(email__iexact=value)

        if not qs.exists():
            raise serializers.ValidationError("No account found with this email (for the resolved tenant).")

        # If multiple users found across tenants and tenant not provided, require tenant header
        if not tenant and qs.count() > 1:
            raise serializers.ValidationError("Multiple accounts found with this email. Please provide tenant context (X-Tenant header).")

        # stash the user instance (choose single one)
        self.user = qs.first()
        return value

    def create(self, validated_data):
        # create one-time token
        token_obj = PasswordResetToken.objects.create(user=self.user)
        # In production: send email with link. For dev return token.
        return {
            "reset_token": token_obj.token,
            "expires_at": token_obj.expires_at,
        }


class PasswordResetSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, attrs):
        try:
            token_obj = PasswordResetToken.objects.get(token=attrs['token'])
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired token.")

        if not token_obj.is_valid():
            raise serializers.ValidationError("Token expired.")

        attrs['token_obj'] = token_obj
        return attrs

    def create(self, validated_data):
        token_obj = validated_data['token_obj']
        user = token_obj.user
        user.set_password(validated_data['password'])
        user.save()
        # consume the token
        token_obj.delete()
        return {"detail": "Password reset successful."}