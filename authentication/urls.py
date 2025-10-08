from django.urls import path
from . import views

urlpatterns = [
    path('social-login/', views.SocialLogin.as_view(), name='social_login'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify-email'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot-password'),
    path('verify-reset-code/', views.VerifyResetCodeView.as_view(), name='verify-reset-code'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
]
