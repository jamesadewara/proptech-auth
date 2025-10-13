from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class TenantAwareBackend(ModelBackend):
    """
    Authenticate by email + tenant.
    Expects authenticate(..., username=email, password=..., tenant=tenant_or_slug_or_instance)
    If request.tenant is set, backend will try to use it as tenant.
    """
    def authenticate(self, request, username=None, password=None, tenant=None, **kwargs):
        if username is None or password is None:
            return None

        tenant_filter = {}
        # tenant could be an instance
        if tenant:
            if hasattr(tenant, 'pk'):
                tenant_filter['tenant'] = tenant
            else:
                # assume slug
                tenant_filter['tenant__slug'] = tenant

        # if middleware set request.tenant and no tenant arg given, use it
        if not tenant_filter and getattr(request, 'tenant', None):
            tenant_filter['tenant'] = request.tenant

        try:
            user = User.objects.get(email__iexact=username, **tenant_filter)
        except User.DoesNotExist:
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
