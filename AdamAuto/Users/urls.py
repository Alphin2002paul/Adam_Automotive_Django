from django.contrib import admin
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),  # Admin interface at the root level
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register, name='register'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('request_password_reset/', views.request_password_reset, name='request_password_reset'),
    path('reset_password_confirm/<str:uidb64>/<str:token>/', views.reset_password_confirm, name='reset_password_confirm'),
    path('logout/', views.logout_view, name='logout'),
    path('main/', views.main, name='main'),
    path('account_dtl/', views.account_dtl, name='account_dtl'),
    path('account_edit/', views.account_edit, name='account_edit'),
    path('auth-receiver/', views.auth_receiver, name='auth_receiver'),
    path('check_email/', views.check_email, name='check_email'),
    path('check_username/', views.check_username, name='check_username'),
    path('update_profile/', views.update_profile, name='update_profile'),
    path('adminindex/', views.adminindex_view, name='adminindex'),
    path('adminadd_dtl/', views.adminadd_dtl, name='adminadd_dtl'),
    path('add_details/', views.add_details, name='add_details'),
    path('adminprofile/', views.adminprofile, name='adminprofile'),
    path('user/<int:user_id>/', views.user_detail, name='user_detail'),
    path('admincaradd_dtl/', views.admincaradd_dtl, name='admincaradd_dtl'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
