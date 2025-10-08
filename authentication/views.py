from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status   
from django.contrib.auth.models import User
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail

from authentication.models import EmailVerification, PasswordResetCode
from authentication.serializers import ChangePasswordSerializer, ForgotPasswordSerializer, LoginSerializer, RegisterSerializer, ResetPasswordSerializer, VerifyEmailSerializer, VerifyResetCodeSerializer
from authentication.utils import send_verification_email
from django.contrib.auth import authenticate, login
import random
from .utils import send_password_reset_email
from rest_framework import permissions

# Create your views here.

class SocialLogin(APIView):
    
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({"error": "Email is required!"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.filter(email=email).first()

        if user:
            return self.login_user(user)
        else:

            username = self.generate_username_from_email(email)
            user = User.objects.create_user(
                email=email,
                username=username,
                password=None
            )
            self.send_account_creation_email(user)
            

            return self.login_user(user)

    def generate_username_from_email(self, email):
        """Generate a unique username from the email."""
        username = email.split('@')[0]

        if User.objects.filter(username=username).exists():

            count = 1
            new_username = f"{username}{count}"
            while User.objects.filter(username=new_username).exists():
                count += 1
                new_username = f"{username}{count}"
            return new_username

        return username

    def send_account_creation_email(self, user):
        """Send a simple account creation email to the user."""
        subject = "Account created successfully"
        message = f"Hi {user.username},\n\nYour account has been created successfully with the email address: {user.email}.\n\nYou can now login."
        from_email = settings.DEFAULT_FROM_EMAIL

        send_mail(subject, message, from_email, [user.email])

    def login_user(self, user):
        """Generate access and refresh tokens for the user and return them."""
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response({
            "message": "Login successful!",
            "refresh": refresh_token,
            "access": access_token,
            # "user": {
            #     "id": user.id,
            #     "email": user.email,
            #     "username": user.username,
            # }
        }, status=status.HTTP_200_OK)



class RegisterView(APIView):
    """
    Step 1: Register User
    """
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = serializer.validated_data['name']
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = User.objects.filter(username=email).first()

        # Case 1: User exists and active
        if user and user.is_active:
            return Response({'error': 'User already exists and is active.'}, status=status.HTTP_400_BAD_REQUEST)

        # Case 2: User exists but inactive — resend OTP
        if user and not user.is_active:
            code = str(random.randint(1000, 9999))
            EmailVerification.objects.create(user=user, code=code)
            send_verification_email(email, code)
            return Response({'message': 'OTP resent. Please verify your email.'}, status=status.HTTP_200_OK)

        # Case 3: New user — create and send OTP
        user = User.objects.create_user(username=email, email=email, password=password, first_name=name)
        user.is_active = False
        user.save()

        code = str(random.randint(1000, 9999))
        EmailVerification.objects.create(user=user, code=code)
        send_verification_email(email, code)

        return Response({'message': 'User created. Please verify your email.'}, status=status.HTTP_201_CREATED)


class VerifyEmailView(APIView):
    """
    Step 2: Verify OTP and Activate Account
    """
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']

        user = User.objects.filter(username=email).first()
        if not user:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        verification = EmailVerification.objects.filter(user=user, code=code).order_by('-created_at').first()
        if not verification:
            return Response({'error': 'Invalid code.'}, status=status.HTTP_400_BAD_REQUEST)

        if verification.is_expired():
            return Response({'error': 'Code expired.'}, status=status.HTTP_400_BAD_REQUEST)

        user.is_active = True
        user.save()

        return Response({'message': 'Email verified successfully! You can now login.'}, status=status.HTTP_200_OK)



class LoginView(APIView):
    """
    Step 3: Login user (JWT token based)
    """
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = authenticate(username=email, password=password)

        if user is None:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_active:
            return Response({'error': 'Please verify your email first.'}, status=status.HTTP_403_FORBIDDEN)

        # ✅ Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        return Response({
            'message': 'Login successful.',
            'access': str(access),
            'refresh': str(refresh),
            # 'user': {
            #     'id': user.id,
            #     'name': user.first_name,
            #     'email': user.email
            # }
        }, status=status.HTTP_200_OK)



class ForgotPasswordView(APIView):
    """
    Step 1: Request password reset (send OTP to email)
    """
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.filter(username=email).first()
        if not user:
            return Response({'error': 'No account found with this email.'}, status=status.HTTP_404_NOT_FOUND)

        code = str(random.randint(1000, 9999))
        PasswordResetCode.objects.create(user=user, code=code)
        send_password_reset_email(email, code)

        return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)


class VerifyResetCodeView(APIView):
    """
    Step 2: Verify reset OTP
    """
    def post(self, request):
        serializer = VerifyResetCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']

        user = User.objects.filter(username=email).first()
        if not user:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        verification = PasswordResetCode.objects.filter(user=user, code=code).order_by('-created_at').first()
        if not verification:
            return Response({'error': 'Invalid code.'}, status=status.HTTP_400_BAD_REQUEST)

        if verification.is_expired():
            return Response({'error': 'Code expired.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'OTP verified. You can now reset your password.'}, status=status.HTTP_200_OK)
    

class ResetPasswordView(APIView):
    """
    Step 3: Reset password after OTP verification
    """
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        new_password = serializer.validated_data['new_password']

        user = User.objects.filter(username=email).first()
        if not user:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password reset successful. You can now login.'}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    """
    Change Password (User must be authenticated)
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']

        user = request.user

        # Check old password
        if not user.check_password(old_password):
            return Response({'error': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

        # Set new password
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)