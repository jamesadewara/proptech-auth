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