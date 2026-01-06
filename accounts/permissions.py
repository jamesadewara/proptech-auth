from rest_framework import permissions

def role_required(role):
    class RolePermission(permissions.BasePermission):
        def has_permission(self, request, view):
            return bool(request.user and request.user.is_authenticated and request.user.role == role and request.user.tenant == getattr(request, 'tenant', None))
    return RolePermission

"""
I.e to use role based permissions
from .permissions import role_required
class SomeView(APIView):
    permission_classes = [role_required('AGENT')]
"""