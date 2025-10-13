from django.contrib.auth import authenticate
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import PasswordResetToken, Tenant, Invite
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer as BaseTokenObtainPairSerializer
from datetime import timedelta
from django.utils import timezone
from django.conf import settings 
from rest_framework import generics, permissions, status, serializers as drf_serializers
from django.db.models import Q

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
    Tenant-aware login using username and password.
    - OWNER: no tenant header required.
    - STAFF / AGENT / GUEST: tenant header required.
    """

    def validate(self, attrs):
        request = self.context.get("request")
        # Prefer an explicit 'username' field from the client. Do NOT rely on
        # self.username_field because in this project USERNAME_FIELD is 'email'.
        raw_username = attrs.get('username')
        # normalize username to include leading '@' like the UserManager does
        if raw_username and isinstance(raw_username, str):
            if not raw_username.startswith('@'):
                raw_username = f"@{raw_username}"
            username = raw_username.lower()
        else:
            username = None

        email = attrs.get("email")
        if email and isinstance(email, str):
            email = email.lower()

        password = attrs.get("password")
        tenant = getattr(request, "tenant", None)
        # Defensive lookups: avoid using .get() which can raise MultipleObjectsReturned
        # We search for a matching user based on username/email and tenant context.
        qs = User.objects.all()
        # If a tenant is present (header/middleware), restrict to it
        if tenant:
            qs = qs.filter(tenant=tenant)

        # Both username and email are expected from the client; filter accordingly
        if username:
            qs = qs.filter(username__iexact=username)
        if email:
            qs = qs.filter(email__iexact=email)

        # If we didn't find any user in the tenant context, we need to decide whether
        # to allow OWNER lookup across tenants (owner may omit tenant header) or to fail.
        user = None
        count = qs.count()
        if count == 1:
            user = qs.first()
        elif count > 1:
            # ambiguous: multiple matches within the same tenant (shouldn't happen due to constraints)
            raise drf_serializers.ValidationError("Multiple accounts matched the provided credentials. Contact support.")
        else:
            # no result within the provided tenant (or no tenant provided)
            # Try owner-bypass: owners are allowed to login without tenant header
            possible = User.objects.filter(username__iexact=username, email__iexact=email)
            if possible.exists():
                # If there's exactly one and it's an OWNER, allow it
                if possible.count() == 1 and possible.first().role == 'OWNER':
                    user = possible.first()
                    # set tenant to owner's tenant for downstream authenticate
                    tenant = user.tenant
                else:
                    # Either multiple users across tenants (ambiguous) or non-owner exists but tenant missing
                    if not tenant:
                        raise drf_serializers.ValidationError(
                            "Tenant header (X-Tenant-Slug) required for non-owner users or ambiguous accounts."
                        )
                    raise drf_serializers.ValidationError(f"No user found for tenant {tenant}.")

        # By now we should have a candidate user or have raised a validation error
        if not user:
            raise drf_serializers.ValidationError("No user found with the supplied credentials.")

        # Determine if tenant header is required for this user
        if user.role != 'OWNER':
            if not tenant:
                raise drf_serializers.ValidationError(
                    "Tenant header (X-Tenant-Slug) required for non-owner users."
                )
            if user.tenant != tenant:
                raise drf_serializers.ValidationError(
                    "Unauthorized: account does not belong to the provided tenant."
                )
        else:
            # For owner, ensure tenant variable represents owner's tenant
            tenant = user.tenant
        # raise serializers.ValidationError(tenant, user.tenant, user.role, "IS IT WORKING")

        # Authenticate using TenantAwareBackend
        auth_user = authenticate(
            request=request,
            username=username,
            email=email,
            password=password,
            tenant=tenant
        )
        if not auth_user:
            raise drf_serializers.ValidationError("Invalid credentials.")

        # We have an authenticated user. Avoid calling super().validate(attrs)
        # because the base implementation may run a global `.get()` on
        # USERNAME_FIELD (email) which can raise MultipleObjectsReturned
        # in multi-tenant setups. Instead, create tokens directly.
        self.user = auth_user

        # Use SimpleJWT's token creation helper
        token = self.get_token(self.user)
        refresh = str(token)
        access = str(token.access_token)

        return {
            'refresh': refresh,
            'access': access,
            'user_id': str(self.user.id),
            'tenant': self.user.tenant.slug if self.user.tenant else None,
            'role': self.user.role,
        }

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