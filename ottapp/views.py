import re
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator


# ---------- REGISTER ----------
def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm = request.POST.get('confirm_password')

        if password != confirm:
            messages.error(request, "Passwords do not match")
            return redirect('register')

        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$'
        if not re.match(pattern, password):
            messages.error(request, "Password must be strong")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return redirect('register')

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_active=False
        )

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        link = f"http://127.0.0.1:8000/verify-email/{uid}/{token}/"

        send_mail(
            "Verify Account",
            f"Click this link:\n{link}",
            settings.EMAIL_HOST_USER,
            [email],
        )

        messages.success(request, "Check your email to activate account")
        return redirect('login')

    return render(request, 'register.html')


# ---------- VERIFY EMAIL ----------
def verify_email(request, uidb64, token):
    uid = force_str(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=uid)

    if default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Account activated")

    return redirect('login')


# ---------- LOGIN ----------
def login_view(request):
    if request.method == 'POST':
        user = authenticate(
            request,
            username=request.POST.get('username'),
            password=request.POST.get('password')
        )

        if user:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, "Please enter correct username or password")

    return render(request, 'login.html')


# ---------- DASHBOARD ----------
@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


# ---------- LOGOUT ----------
def logout_view(request):
    logout(request)
    return redirect('login')


# ---------- FORGOT PASSWORD ----------
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()

        if not user:
            messages.error(request, "Email not found")
            return redirect('forgot_password')

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        link = f"http://127.0.0.1:8000/reset-password/{uid}/{token}/"

        send_mail(
            "Reset Password",
            f"Reset link:\n{link}",
            settings.EMAIL_HOST_USER,
            [email],
        )

        messages.success(request, "Reset link sent")
        return redirect('login')

    return render(request, 'forgot_password.html')


# ---------- RESET PASSWORD ----------
def reset_password(request, uidb64, token):
    uid = force_str(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=uid)

    if request.method == 'POST':
        password = request.POST.get('password')
        user.set_password(password)
        user.save()
        messages.success(request, "Password updated")
        return redirect('login')

    return render(request, 'reset_password.html')
