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
    path('api/service/<int:service_id>/', views.get_service_details, name='get_service_details'),
    path('user-details/<int:user_id>/',views.get_user_details, name='get_user_details'),
    path('approve-service/<int:service_id>/', views.approve_service, name='approve_service'),
    path('deny-service/<int:service_id>/', views.deny_service, name='deny_service'),
    path('request_dtl/', views.request_dtl, name='request_dtl'),
    path('update_service/<int:service_id>/', views.update_service, name='update_service'),
    path('delete_service/<int:service_id>/', views.delete_service, name='delete_service'),
    path('sell-car/', views.sellcar_dtl, name='sellcar_dtl'),
    path('check-registration-number/', views.check_registration_number, name='check_registration_number'),
    path('salereq_dsply/', views.salereq_dsply, name='salereq_dsply'),
    path('salemore_dtl/<int:car_id>/', views.salemore_dtl, name='salemore_dtl'),
    path('get_user_details/<int:car_id>/', views.get_user_details, name='get_user_details'),
    path('cancel_car_listing/<int:car_id>/', views.cancel_car_listing, name='cancel_car_listing'),
    path('approve_car_listing/<int:car_id>/', views.approve_car_listing, name='approve_car_listing'),
    path('feedback_dtl/', views.feedback_dtl, name='feedback_dtl'),
    # path('predict_recommendation/', views.predict_recommendation, name='predict_recommendation'),
    # path('prediction_result/', views.prediction_result, name='prediction_result'),
    # path('get_predictions/<int:car_id>/', views.get_predictions, name='get_predictions'),
    path('process_payment/', views.process_payment, name='process_payment'),
    path('book-test-drive/', views.book_test_drive, name='book_test_drive'),
    path('get-available-slots/', views.get_available_slots, name='get_available_slots'),
    path('admintestdrive/', views.admintestdrive, name='admintestdrive'),
    path('get-test-drive-user-details/<int:user_id>/', views.get_test_drive_user_details, name='get_test_drive_user_details'),
    path('approve-test-drive/', views.approve_test_drive, name='approve_test_drive'),
    path('mybookings/', views.mybookings, name='mybookings'),
    path('get_predictions/<int:car_id>/', views.get_predictions, name='get_predictions'),
    path('soldcars/', views.soldcars, name='soldcarinfo'),
    path('salemore_dtl2/<int:car_id>/', views.salemore_dtl2, name='salemore_dtl2'),
    path('get_user_details2/<int:user_id>/', views.get_user_details2, name='get_user_details2'),
    path('generate_receipt_pdf/<int:purchase_id>/', views.generate_receipt_pdf, name='generate_receipt_pdf'),
    path('enquirecar/', views.enquire_car, name='enquirecar'),  # Changed from 'enquire-car/' to 'enquirecar/'
    path('submit-enquiry/', views.submit_enquiry, name='submit_enquiry'),
    path('check_existing_enquiry/', views.check_existing_enquiry, name='check_existing_enquiry'),
    path('adminenquiry/', views.adminenquiry, name='adminenquiry'),
    path('get_enquiry_details/<int:enquiry_id>/', views.get_enquiry_details, name='get_enquiry_details'),
    path('approve_enquiry/', views.approve_enquiry, name='approve_enquiry'),
    path('update_sale/<int:id>/', views.update_sale, name='update_sale'),
    path('delete_sale/<int:id>/', views.delete_sale, name='delete_sale'),
    path('update_test_drive/<int:id>/', views.update_test_drive, name='update_test_drive'),
    path('delete_test_drive/<int:test_drive_id>/', views.delete_test_drive, name='delete_test_drive'),
    path('update_enquiry/<int:id>/', views.update_enquiry, name='update_enquiry'),
    path('delete_enquiry/<int:enquiry_id>/', views.delete_enquiry, name='delete_enquiry'),
    path('check-existing-booking/', views.check_existing_booking, name='check_existing_booking'),
    path('get_available_time_slots/<int:id>/<str:date>/', views.get_available_time_slots, name='get_available_time_slots'),
    path('download_receipt/<int:car_id>/', views.download_receipt, name='download_receipt'),
    path('change-password/', views.change_password, name='change_password'),
    path('adminfeedback/', views.adminfeedback, name='adminfeedback'),
    path('deny-test-drive/', views.deny_test_drive, name='deny_test_drive'),
    


    







]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)