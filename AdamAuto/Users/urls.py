from django.contrib import admin
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from .views import update_user_status


urlpatterns = [
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
    path('update_user_status/<int:user_id>/', update_user_status, name='update_user_status'),
    path('userdisplaycars_dtl/', views.userdisplaycars_dtl, name='userdisplaycars_dtl'),
    path('userdisplaycarnologin_dtl/', views.userdisplaycarnologin_dtl, name='userdisplaycarnologin_dtl'),
    path('toggle_like/<int:car_id>/', views.toggle_like, name='toggle_like'),
    path('userdisplaycars_dtl/', views.userdisplaycars_dtl, name='userdisplaycars_dtl'),
    path('liked_list/', views.liked_list, name='liked_list'),
    path('userdisplaycars/', views.userdisplaycars_dtl, name='userdisplaycars_dtl'),
    path('edit-listing/', views.edit_listing, name='edit_listing'),
    path('speccaredit_dtl/', views.speccaredit_dtl, name='speccaredit_dtl'),
    path('toggle_car_status/<int:car_id>/', views.toggle_car_status, name='toggle_car_status'),
    path('speccaredit_dtl/<int:car_id>/', views.speccaredit_dtl, name='speccaredit_dtl'),
    path('car/<int:car_id>/', views.morecar_dtl, name='car_detail'),
    path('category_edit/', views.category_edit, name='category_edit'),
    path('delete_category/', views.delete_category, name='delete_category'),
    path('update_category/', views.update_category, name='update_category'),
    path('send_disable_email/<int:user_id>/', views.send_disable_email, name='send_disable_email'),
    path('get_disable_reason/<int:user_id>/', views.get_disable_reason, name='get_disable_reason'),
    path('bookservice_dtl/', views.bookservice_dtl, name='bookservice_dtl'),
    path('sellcar_dtl/', views.sellcar_dtl, name='sellcar_dtl'),
    path('service_request_view/', views.service_request_view, name='service_request_view'),



]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
