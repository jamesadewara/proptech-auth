from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db.models import Q

User = get_user_model()

class TenantAwareBackend(ModelBackend):
    """
    Authenticate by email + tenant.
    If tenant is not provided and multiple users exist, return None.
    """
    def authenticate(self, request, username=None, email=None, password=None, tenant=None, **kwargs):
        """
        Authenticate by email + username + tenant when provided.

        Behaviour:
        - If tenant is provided (slug or Tenant instance) use it to filter.
        - If tenant is not provided, but request.tenant exists, use that.
        - If multiple users match (ambiguity) return None so the caller can surface a clear error.
        - Only return a user when password matches and user_can_authenticate(user) is True.
        """
        # require identification fields
        if (username is None and email is None) or password is None:
            return None
        
        # Normalize username/email queries
        username_q = username.lower() if isinstance(username, str) else None
        email_q = email.lower() if isinstance(email, str) else None

        # Build tenant filter
        tenant_filter = {}
        if tenant:
            # tenant can be slug or model
            if hasattr(tenant, 'pk'):
                tenant_filter['tenant'] = tenant
            else:
                tenant_filter['tenant__slug'] = tenant
        elif getattr(request, 'tenant', None):
            tenant_filter['tenant'] = request.tenant

        # Build Q lookup: support lookups by username OR email depending on provided fields
        qs = User.objects.all()
        if tenant_filter:
            qs = qs.filter(**tenant_filter)

        lookups = Q()
        if username_q:
            lookups &= Q(username__iexact=username_q)
        if email_q:
            lookups &= Q(email__iexact=email_q)

        if not (username_q or email_q):
            return None

        qs = qs.filter(lookups)

        # If no user or ambiguous, return None (let the serializer surface a helpful message)
        count = qs.count()
        if count == 0:
            return None
        if count > 1:
            return None

        user = qs.first()
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
