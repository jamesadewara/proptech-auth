from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from .models import Tenant

class TenantMiddleware(MiddlewareMixin):
    """
    Attach Tenant instance to request.tenant.
    Priority:
      1) X-Tenant-Slug header
      2) tenant_slug field in POST body
      3) subdomain of Host header (like goldenstate.example.com -> goldenstate)
    """

    HEADER = "HTTP_X_TENANT_SLUG"  # Django stores headers as HTTP_*

    def process_request(self, request):
        request.tenant = None
        # 1) header
        slug = request.META.get(self.HEADER)
        if slug:
            try:
                request.tenant = Tenant.objects.get(slug=slug)
                return
            except Tenant.DoesNotExist:
                request.tenant = None

        # 2) body (works for JSON if request.body read by DRF)
        if hasattr(request, 'data'):
            slug = request.data.get('tenant_slug') if isinstance(request.data, dict) else None
            if slug:
                try:
                    request.tenant = Tenant.objects.get(slug=slug)
                    return
                except Tenant.DoesNotExist:
                    request.tenant = None

        # 3) subdomain (Host header)
        host = request.get_host().split(':')[0]  # remove port
        if host and '.' in host:
            sub = host.split('.')[0]
            try:
                request.tenant = Tenant.objects.get(domain=sub)
            except Tenant.DoesNotExist:
                request.tenant = None
