# utils.py
from django.core.mail import send_mail
from django.conf import settings

def send_verification_email(email, code):
    subject = "Your Account Verification Code"
    message = f"Your OTP code is: {code}\nThis code expires in 3 minutes."
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])


def send_password_reset_email(email, code):
    subject = "Your Password Reset Code"
    message = f"Your OTP code to reset your password is: {code}\nThis code expires in 3 minutes."
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])