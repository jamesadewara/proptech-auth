from django.contrib.auth import authenticate
from rest_framework import serializers
from django.contrib.auth import get_user_model

from accounts.utils.email_utils import send_html_email
from .models import PasswordResetToken, Tenant, Invite
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer as BaseTokenObtainPairSerializer
from datetime import timedelta
from django.utils import timezone
from django.conf import settings 
from rest_framework import generics, permissions, status, serializers as drf_serializers
from django.db.models import Q
import requests 

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


class GoogleSocialLoginSerializer(serializers.Serializer):
    credential = serializers.CharField(required=True)
    name = serializers.CharField(required=False)
    slug = serializers.CharField(required=False)

    def _make_unique_tenant_slug(self, base: str) -> str:
        slug_base = base.lower()
        slug = slug_base
        counter = 1
        while Tenant.objects.filter(slug=slug).exists():
            slug = f"{slug_base}{counter}"
            counter += 1
        return slug

    def _make_unique_username(self, base: str) -> str:
        # ensure leading '@' and lowercase
        username_base = f"@{base.lstrip('@').lower()}"
        username = username_base
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{username_base}{counter}"
            counter += 1
        return username

    def create_owner(self, email, name=None, picture=None):
        """
        Create a new Tenant + OWNER user.
        Uses self.initial_data['slug'] or derived slug from email prefix.
        Uses self.initial_data['name'] or provided name for tenant name.
        """
        # prefer explicit slug if given
        requested_slug = (self.initial_data.get("slug") or "").strip()
        slug_base = requested_slug or email.split("@")[0]
        slug = self._make_unique_tenant_slug(slug_base)

        tenant_name = self.initial_data.get("name") or name or slug_base
        tenant = Tenant.objects.create(name=tenant_name, slug=slug)

        username_base = slug_base  # owner username based on tenant slug/email prefix
        username = self._make_unique_username(username_base)

        owner = User.objects.create_user(
            email=email,
            username=username,
            tenant=tenant,
            role="OWNER",
        )

        # attach picture if provided (assumes profile_picture is a CharField / URLField or similar)
        if picture:
            try:
                owner.profile_picture = picture
                owner.save(update_fields=["profile_picture"])
            except Exception:
                # if saving profile_picture fails for any reason, ignore but keep owner created
                pass

        return tenant, owner

    def create_guest(self, tenant, email, name=None, picture=None):
        """
        Create a new guest/staff/agent user under an existing tenant.
        Ensures username uniqueness globally.
        """
        username_candidate = email.split("@")[0]
        username = self._make_unique_username(username_candidate)

        user, created = User.objects.get_or_create(
            email=email,
            tenant=tenant,
            defaults={
                "username": username,
                "role": "GUEST",
            },
        )

        # update profile/name/picture for existing users if needed
        updated_fields = []
        if name and getattr(user, "full_name", None) != name:
            # set attribute only if it exists on the model
            if hasattr(user, "full_name"):
                user.full_name = name
                updated_fields.append("full_name")
        if picture and getattr(user, "profile_picture", None) != picture:
            user.profile_picture = picture
            updated_fields.append("profile_picture")
        if updated_fields:
            user.save(update_fields=updated_fields)

        return user

    def validate(self, attrs):
        credential = attrs.get("credential")
        request = self.context.get("request")
        # prefer middleware's request.tenant if set, fallback to header
        tenant_from_mw = getattr(request, "tenant", None)
        tenant_slug_header = request.headers.get("X-Tenant-Slug")
        # prefer middleware-resolved tenant (more reliable)
        tenant_slug = tenant_from_mw.slug if tenant_from_mw else (tenant_slug_header or None)

        # Verify Google ID token with correct parameter name (id_token)
        verify_url = settings.GOOGLE_OAUTH2_VERIFY_URL  # expected to be "https://oauth2.googleapis.com/tokeninfo"
        response = requests.get(verify_url, params={"id_token": credential})
        data = response.json()

        if response.status_code != 200 or "error" in data:
            raise serializers.ValidationError("Invalid Google token.")

        email = data.get("email")
        name = data.get("name", "")
        picture = data.get("picture", "")

        if not email:
            raise serializers.ValidationError("Google account has no email.")

        # If tenant_slug present -> must be a tenant user (guest/staff/agent)
        if tenant_slug:
            # resolve tenant object
            try:
                tenant = Tenant.objects.get(slug=tenant_slug)
            except Tenant.DoesNotExist:
                raise serializers.ValidationError("Invalid tenant slug.")

            user = self.create_guest(tenant, email, name, picture)
            attrs.update({"tenant": tenant, "user": user, "created": getattr(user, "_state", None) is None})
            # note: created flag is handled by client if needed; we set created=False for get_or_create existing
            return attrs

        # No tenant provided -> owner path MUST be used
        # If an OWNER already exists with this email -> sign them in
        existing_owner = User.objects.filter(email__iexact=email, role="OWNER").first()
        if existing_owner:
            attrs.update({"tenant": existing_owner.tenant, "user": existing_owner, "created": False})
            return attrs

        # If no owner exists, create one BUT require name and slug be provided by client
        provided_name = (self.initial_data.get("name") or "").strip()
        provided_slug = (self.initial_data.get("slug") or "").strip()

        if not provided_name or not provided_slug:
            raise serializers.ValidationError(
                "New owner registration requires 'name' and 'slug' in request body when no tenant header is provided."
            )

        # Ensure requested slug is not taken by other tenants
        if Tenant.objects.filter(slug=provided_slug).exists():
            raise serializers.ValidationError("Requested tenant slug is already taken. Pick another slug.")

        # Create owner and tenant
        tenant, owner = self.create_owner(email=email, name=provided_name, picture=picture)
        attrs.update({"tenant": tenant, "user": owner, "created": True})
        return attrs

# --- Tenant-aware login using tenant from middleware/header ---
class TenantTokenObtainPairSerializer(BaseTokenObtainPairSerializer):
    """
    Tenant-aware login using username and password.
    - OWNER: no tenant header required.
    - STAFF / AGENT / GUEST: tenant header required.
    """

    def validate(self, attrs):
        request = self.context.get("request")
        
        # Extract credentials
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        email = attrs.get('email', username)  # Username field might contain email
        
        # First check if this is an owner account
        if email:
            owner = User.objects.filter(email__iexact=email, role='OWNER').first()
            if owner:
                # We found an owner, try to authenticate them
                auth_user = authenticate(request, email=email, password=password)
                if auth_user:
                    # Owner authentication successful
                    refresh = self.get_token(auth_user)
                    return {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'user_id': str(auth_user.id),
                        'tenant': auth_user.tenant.slug,
                        'role': auth_user.role,
                        'is_active': auth_user.is_active,
                        'email_verified': auth_user.email_verified,
                    }
                else:
                    # Owner exists but password is wrong
                    raise serializers.ValidationError({
                        'detail': 'Invalid credentials for owner account'
                    })
                    
        # If we get here, either:
        # 1. No owner account exists with this email
        # 2. User is trying to login as non-owner
        # Proceed with tenant-aware auth
        tenant = getattr(request, 'tenant', None)
        if not tenant:
            raise serializers.ValidationError(
                "Tenant header is required for non-owner login."
            )
        # For non-owner login, we need username/email and tenant
        raw_username = username
        if raw_username and isinstance(raw_username, str):
            if not raw_username.startswith('@'):
                raw_username = f"@{raw_username}"
            username = raw_username.lower()
        
        if email and isinstance(email, str):
            email = email.lower()
            
        # Attempt authentication with tenant context
        user = authenticate(
            request,
            username=username,
            email=email,
            password=password,
            tenant=tenant
        )

        # Special handling for owners - they can login without tenant header
        if user.role == 'OWNER':
            # For owners, always use their tenant regardless of header
            tenant = user.tenant
            # If a tenant header was provided, warn if it doesn't match (but still allow login)
            if getattr(request, "tenant", None) and request.tenant != user.tenant:
                print(f"Warning: Owner login with mismatched tenant header. Expected {user.tenant.slug}")
        else:
            # Non-owners must provide correct tenant header
            if not tenant:
                raise drf_serializers.ValidationError(
                    "Tenant header (X-Tenant-Slug) required for non-owner users."
                )
            if user.tenant != tenant:
                raise drf_serializers.ValidationError(
                    "Unauthorized: account does not belong to the provided tenant."
                )

        # Authenticate using TenantAwareBackend with clear error distinction
        try:
            auth_user = authenticate(
                request=request,
                username=username,
                email=email,
                password=password,
                tenant=tenant
            )
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            auth_user = None

        if not auth_user:
            if user.role == 'OWNER':
                raise drf_serializers.ValidationError({
                    "error": "Owner login failed. Please check your credentials.",
                    "debug": {
                        "email": email,
                        "is_owner": True,
                        "tenant": tenant.slug if tenant else None
                    }
                })

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
            'is_active': self.user.is_active,
            'email_verified': self.user.email_verified,
            'username': self.user.username,
            'email': self.user.email,
            'id': str(self.user.id),
            'is_staff': self.user.is_staff,
            'is_superuser': self.user.is_superuser,
            'date_joined': self.user.date_joined,
            'profile_picture': self.user.profile_picture.url if self.user.profile_picture else None
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
        fields = ('id','email','username','role','tenant','is_active','is_staff','is_superuser','date_joined','email_verified','profile_picture')
        read_only_fields = ('id','tenant','role','is_active','is_staff','is_superuser','date_joined','email_verified')

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
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token_obj.token}"

        send_html_email(
            subject="Password Reset Request",
            to_email=self.user.email,
            template_name="accounts/email/password_reset_email.html",
            context={"user": self.user, "reset_url": reset_url},
        )
        # In production: send email with link. For dev return token.
        return {
            "reset_token": token_obj.token,
            "expires_at": token_obj.expires_at,
        }


class PasswordResetSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, attrs):
        # Use filter().first() instead of get() to avoid MultipleObjectsReturned
        token_obj = PasswordResetToken.objects.filter(token=attrs['token']).first()
        
        if not token_obj:
            raise serializers.ValidationError("Invalid or expired token.")

        if not token_obj.is_valid():
            raise serializers.ValidationError("Token expired.")
            
        # Ensure we have tenant context if needed
        request = self.context.get('request')
        tenant = getattr(request, 'tenant', None)
        
        # If tenant header provided, verify token belongs to user in that tenant
        if tenant and token_obj.user.tenant != tenant:
            raise serializers.ValidationError("Token does not match the provided tenant context.")

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