from django.contrib import admin
from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),  # Admin interface at the root level
    path('', views.index, name='index'),
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('request_password_reset/', views.request_password_reset, name='request_password_reset'),
    path('reset_password_confirm/<str:uidb64>/<str:token>/', views.reset_password_confirm, name='reset_password_confirm'),

    path('sign-out', views.sign_out, name='sign_out'),
    path('auth-receiver', views.auth_receiver, name='auth_receiver'),
]

