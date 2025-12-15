from django.urls import path
from .views import *

urlpatterns = [
    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('verify-email/<uidb64>/<token>/', verify_email),
    path('dashboard/', dashboard, name='dashboard'),
    path('logout/', logout_view),
    path('forgot-password/', forgot_password),
    path('reset-password/<uidb64>/<token>/', reset_password),
]
