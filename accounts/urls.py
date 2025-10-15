from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from .views import GoogleSocialLoginView, InviteAcceptView, InviteCreateView, MeView, PasswordForgotView, PasswordResetView, RegisterTenantView, LogoutView, TenantTokenObtainPairView, DeleteAccountView, RemoveStaffView

urlpatterns = [
    path('register/tenant/', RegisterTenantView.as_view(), name='register_tenant'),
    path('invite/create/', InviteCreateView.as_view(), name='invite_create'),
    path('invite/accept/', InviteAcceptView.as_view(), name='invite_accept'),
    path('social-login/google/', GoogleSocialLoginView.as_view(), name='google-social-login'),
    path('login/', TenantTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('me/', MeView.as_view(), name='me'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('password/forgot/', PasswordForgotView.as_view(), name='password_forgot'),
    path('password/reset/', PasswordResetView.as_view(), name='password_reset'),
    path('remove/staff/', RemoveStaffView.as_view(), name='remove_staff'),
    path('delete/account/', DeleteAccountView.as_view(), name='delete_account'),
    path('logout/', LogoutView.as_view(), name='logout')
]