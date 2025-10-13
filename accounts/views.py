from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import generics, permissions, status, serializers as drf_serializers
from .serializers import (
    PasswordForgotSerializer,
    PasswordResetSerializer,
    RegisterTenantSerializer,
    InviteCreateSerializer,
    InviteAcceptSerializer,
    TenantTokenObtainPairSerializer,
    UserSerializer,
)
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate
from .models import User

# --- helper permission ---
class IsTenantOwner(permissions.BasePermission):
    def has_permission(self, request, view):
        u = request.user
        if not (u and u.is_authenticated):
            return False
        # prefer middleware tenant, fallback to the user's tenant
        tenant = getattr(request, 'tenant', None) or getattr(u, 'tenant', None)
        return bool(u.role == 'OWNER' and u.tenant == tenant)


# --- Tenant registration ---
class RegisterTenantView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterTenantSerializer

    @extend_schema(request=RegisterTenantSerializer, responses={201: OpenApiResponse(description="Tenant and owner created")})
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        owner = serializer.save()
        token = RefreshToken.for_user(owner)
        return Response({
            'tenant': owner.tenant.slug,
            'user': UserSerializer(owner).data,
            'access': str(token.access_token),
            'refresh': str(token)
        }, status=status.HTTP_201_CREATED)

class TenantTokenObtainPairView(TokenObtainPairView):
    """
    Simple wrapper view to use TenantTokenObtainPairSerializer.
    """
    serializer_class = TenantTokenObtainPairSerializer

    @extend_schema(request=TenantTokenObtainPairSerializer, responses={200: OpenApiResponse(description="Token pair with tenant info")})
    def post(self, request, *args, **kwargs):
        # tenant should be set by TenantMiddleware (or via X-Tenant-Slug header)
        serializer = self.get_serializer(data=request.data)
        serializer.context['request'] = request  # ensure request context is passed
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


# --- Invite creation (OWNER only) ---
class InviteCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated, IsTenantOwner]
    serializer_class = InviteCreateSerializer

    @extend_schema(request=InviteCreateSerializer, responses={201: OpenApiResponse(description="Invite created")})
    def post(self, request, *args, **kwargs):
        # request.tenant must be set (middleware)
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        invite = serializer.save()
        # Send email in production. For dev, return token/url in response.
        accept_url = f"{request.build_absolute_uri('/')}api/v1/invite/accept/?token={invite.token}"
        # In production call send_mail(...)
        return Response({'invite_link': accept_url, 'email': invite.email, 'expires_at': invite.expires_at}, status=status.HTTP_201_CREATED)


# --- Accept invite ---
class InviteAcceptView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = InviteAcceptSerializer

    @extend_schema(request=InviteAcceptSerializer, responses={201: UserSerializer})
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'access': str(token.access_token),
            'refresh': str(token)
        }, status=status.HTTP_201_CREATED)
        
class RemoveStaffView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = User.objects.all()

    def delete(self, request, *args, **kwargs):
        user_id = kwargs.get("user_id")
        target_user = User.objects.filter(id=user_id, tenant=request.tenant).first()

        if not target_user:
            return Response({"error": "User not found or not part of your tenant."}, status=404)

        if target_user.role == 'OWNER':
            return Response({"error": "You cannot remove the owner account."}, status=403)

        target_user.delete()
        return Response({"success": f"{target_user.email} removed successfully."}, status=200)

# --- /me endpoint ---
class MeView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    @extend_schema(responses=UserSerializer)
    def get(self, request, *args, **kwargs):
        return Response(self.get_serializer(request.user).data)


class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Logged out"})
        except Exception:
            return Response({"error": "Invalid token"}, status=400)
        
class PasswordForgotView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordForgotSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        # In prod: don't return token in the response. Send via email instead.
        return Response(result, status=status.HTTP_200_OK)


class PasswordResetView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response(result, status=status.HTTP_200_OK)

class DeleteAccountView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        user = request.user
        user_email = user.email
        user.delete()
        return Response({"message": f"Account {user_email} deleted successfully."}, status=200)
