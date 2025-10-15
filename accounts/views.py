from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework import generics, permissions, status, serializers as drf_serializers
from .serializers import (
    GoogleSocialLoginSerializer,
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
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate
from .models import Tenant, User
from rest_framework.views import APIView
import requests
from django.conf import settings
from rest_framework.permissions import AllowAny

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


class GoogleSocialLoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = GoogleSocialLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user:User = serializer.validated_data["user"]
        tenant:Tenant = serializer.validated_data["tenant"]
        created = serializer.validated_data["created"]

        refresh = RefreshToken.for_user(user)

        return Response({
            "tenant": tenant.slug,
            "user": {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "role": user.role,
                "profile_picture": user.profile_picture.url if user.profile_picture else None,
                "tenant": tenant.slug
            },
            "created": created,
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }, status=status.HTTP_200_OK)

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
    permission_classes = [permissions.IsAuthenticated, IsTenantOwner]  # Only owners can remove staff
    queryset = User.objects.all()

    def delete(self, request, *args, **kwargs):
        if not request.tenant:
            return Response(
                {"error": "Tenant context required. Provide X-Tenant-Slug header."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Try to get user_id from URL params first, then request body
        user_id = request.query_params.get("user_id") or request.data.get("user_id")
        
        if not user_id:
            return Response(
                {"error": "user_id is required either in URL (?user_id=...) or request body"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            target_user = User.objects.filter(
                id=user_id, 
                tenant=request.tenant
            ).first()
        except (ValueError, TypeError):
            return Response(
                {"error": f"Invalid user_id format: {user_id}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        if not target_user:
            return Response(
                {"error": f"User with id {user_id} not found in tenant {request.tenant.slug}"}, 
                status=status.HTTP_404_NOT_FOUND
            )

        if target_user.role == 'OWNER':
            return Response(
                {"error": "You cannot remove the owner account."}, 
                status=status.HTTP_403_FORBIDDEN
            )

        if target_user.id == request.user.id:
            return Response(
                {"error": "You cannot remove your own account. Use the delete account endpoint instead."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        email = target_user.email
        tenant_slug = request.tenant.slug
        target_user.delete()
        
        return Response({
            "success": f"User {email} removed successfully from tenant {tenant_slug}.",
            "detail": {
                "removed_user_id": user_id,
                "removed_user_email": email,
                "tenant": tenant_slug
            }
        }, status=status.HTTP_200_OK)

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
        # Try to obtain a refresh token from request body first, then from Authorization header.
        token_str = None
        if isinstance(request.data, dict) and request.data.get("refresh"):
            token_str = request.data.get("refresh")
        else:
            auth = request.META.get("HTTP_AUTHORIZATION", "")
            if auth.startswith("Bearer "):
                token_str = auth.split(" ", 1)[1].strip()

        if not token_str:
            return Response(
                {"error": "No token provided. Send refresh token in body as {'refresh': '<token>'} or include it in Authorization header."},
                status=400,
            )

        try:
            token = RefreshToken(token_str)
            # blacklist() requires the blacklist app to be installed; this will raise TokenError for invalid tokens.
            token.blacklist()
            return Response({"detail": "Logged out"})
        except TokenError:
            return Response({"error": "Invalid or unsupported token. Provide a refresh token to log out."}, status=400)
        except Exception:
            return Response({"error": "Could not process token."}, status=400)
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
        
        # Cannot delete if no tenant context (except OWNER)
        if not request.tenant and user.role != 'OWNER':
            return Response(
                {"error": "Tenant context required. Provide X-Tenant-Slug header."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # For non-owners, verify tenant matches
        if user.role != 'OWNER' and user.tenant != request.tenant:
            return Response(
                {"error": "Account does not belong to the provided tenant."}, 
                status=status.HTTP_403_FORBIDDEN
            )

        # Owners cannot be deleted through this endpoint
        if user.role == 'OWNER':
            return Response(
                {"error": "Owner accounts cannot be deleted through this endpoint."}, 
                status=status.HTTP_403_FORBIDDEN
            )

        user_email = user.email
        tenant_slug = user.tenant.slug
        user.delete()
        
        return Response({
            "message": f"Account {user_email} deleted successfully from tenant {tenant_slug}."
        }, status=status.HTTP_200_OK)
