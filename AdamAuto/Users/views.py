from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .models import User
from django.contrib.auth import authenticate, login as auth_login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import random
import os
from google.oauth2 import id_token
from google.auth.transport import requests
import jwt
from .decorators import nocache
from django.shortcuts import render, get_object_or_404

users = get_user_model()

class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return str(user.pk) + str(timestamp)

token_generator = CustomTokenGenerator()

def generate_otp():
    return random.randint(100000, 999999)
@nocache
def login_view(request):
    user = request.user
    if user.is_authenticated:
        if user.user_type=="admin":
             return redirect('adminindex')
        if user.user_type=="customer":
             return redirect('main')
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        
        # # Standard authentication
        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            auth_login(request, user)
            # messages.success(request, 'Logged in successfully.')
            if user.user_type=="admin":
                 return redirect('adminindex')
            if user.user_type=="customer":
                 return redirect('main')
        else:
            messages.error(request, 'Invalid email or password.')
            return redirect('login')
    
    return render(request, 'login.html')
@nocache
def index(request):
    return render(request, 'index.html')

@login_required
@nocache
def main(request):
    return render(request, 'main.html')

def forgetpass(request):
    return render(request, 'forgetpass.html')

@login_required
@nocache
def account_dtl(request):
    return render(request, 'account_dtl.html')

@login_required
@nocache
def account_edit(request):
    return render(request, 'account_edit.html')
@nocache
def register(request):
    if request.method == 'POST':
        fname = request.POST['name']
        lname = request.POST['name1']
        phone = request.POST['phone']
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']

        try:
            otp = generate_otp()
            request.session['otp'] = otp
            request.session['user_details'] = {
                'first_name': fname,
                'last_name': lname,
                'phone': phone,
                'email': email,
                'username': username,
                'password': password,
            }

            # Send OTP to user's email
            send_mail(
                'Your OTP for logging in',
                f'Your OTP is {otp}',
                'your-email@gmail.com',
                [email],
                fail_silently=False,
            )

            messages.success(request, f"Account created for {username}. Check your email for the OTP.")
            return redirect(reverse('verify_otp'))
        
        except Exception as e:
            messages.error(request, f"Error creating account: {str(e)}")
            return redirect('register')

    return render(request, 'register.html')

def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST['otp']
        session_otp = request.session.get('otp')
        user_details = request.session.get('user_details')

        if not user_details or not session_otp:
            messages.error(request, "Session expired or invalid data. Please try registering again.")
            return redirect('register')

        if otp == str(session_otp):
            try:
                user = users.objects.create(
                    first_name=user_details['first_name'],
                    last_name=user_details['last_name'],
                    email=user_details['email'],
                    username=user_details['username'],
                    Phone_number=user_details['phone'],
                    user_type='customer'
                )
                user.set_password(user_details['password'])  # Hash the password
                user.save()

                # Clear session data
                del request.session['otp']
                del request.session['user_details']

                messages.success(request, "OTP verified. You can now sign in.")
                return redirect('login')
            except Exception as e:
                messages.error(request, f"Error saving user: {str(e)}")
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, 'verify_otp.html')

def request_password_reset(request):
    if request.method == 'POST':
        email = request.POST['email']
        try:
            user = users.objects.get(email=email)
            
            # Generate a password reset token and send it to the user's email
            token = token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            
            reset_url = reverse('reset_password_confirm', kwargs={'uidb64': uidb64, 'token': token})
            reset_url = request.build_absolute_uri(reset_url)
            
            send_mail(
                'Password Reset Request',
                f'Click the following link to reset your password: {reset_url}',
                'your-email@gmail.com',
                [email],
                fail_silently=False,
            )
            
            messages.success(request, 'Password reset email has been sent. Check your email to proceed.')
            return redirect('request_password_reset')
        
        except users.DoesNotExist:
            messages.error(request, 'User does not exist.')
            return redirect('request_password_reset')

    return render(request, 'password_reset/request_password_reset.html')

def reset_password_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = users.objects.get(pk=uid)
        
        if token_generator.check_token(user, token):
            if request.method == 'POST':
                new_password = request.POST['new_password']
                confirm_password = request.POST['confirm_password']
                
                if new_password == confirm_password:
                    user.password = new_password
                    user.save()
                    messages.success(request, 'Password reset successful. You can now sign in with your new password.')
                    return redirect('login')
                else:
                    messages.error(request, 'Passwords do not match. Please try again.')
                    return render(request, 'password_reset/reset_password_confirm.html', {'uidb64': uidb64, 'token': token})
            
            return render(request, 'password_reset/reset_password_confirm.html', {'uidb64': uidb64, 'token': token})
        
        else:
            messages.error(request, 'Invalid password reset link.')
            return redirect('index')
    
    except (TypeError, ValueError, OverflowError, users.DoesNotExist):
        user = None
    
    return redirect('login')

def sign_in(request):
    return render(request, 'sign_in.html')

@csrf_exempt
def auth_receiver(request):
    token = request.POST['credential']

    try:
        user_data = id_token.verify_oauth2_token(
            token, requests.Request(), os.environ['GOOGLE_OAUTH_CLIENT_ID']
        )
    except ValueError:
        return HttpResponse(status=403)

    request.session['user_data'] = user_data
    return redirect('sign_in')
@nocache
def logout_view(request):
    request.session.flush()
    return redirect('index')

@login_required
def main_view(request):
    return render(request, 'main.html')

def auth_receiver(request):
    return redirect('main')

def check_email(request):
    email = request.POST.get('email')
    exists = User.objects.filter(email=email).exists()
    return JsonResponse({'exists': exists})

def check_username(request):
    username = request.POST.get('username')
    exists = User.objects.filter(username=username).exists()
    return JsonResponse({'exists': exists})

def update_profile(request):
    if request.method == 'POST':
        customer = request.user  # Corrected attribute to get the logged-in user
        customer.first_name = request.POST.get('first_name')
        customer.last_name = request.POST.get('last_name')
        # customer.username = request.POST.get('username')
        # customer.email = request.POST.get('email')
        customer.Phone_number = request.POST.get('Phone_number')  # Ensure case matches the model field
        customer.address = request.POST.get('address')
        if 'photo' in request.FILES:
            customer.profile_picture = request.FILES['photo']  # Ensure the correct field name
        customer.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('account_dtl')
    return render(request, 'account_dtl.html', {'user': request.user})

@login_required
@nocache
def adminindex_view(request):
    users = User.objects.filter(is_superuser=False)
    return render(request, 'adminindex.html', {'users': users})

# @login_required
@nocache
def adminadd_dtl(request):
    return render(request, 'adminadd_dtl.html')

from django.shortcuts import render, redirect
from .models import Tbl_Company, Tbl_Color, Tbl_Model,VehicleType,UserCarDetails

def add_details(request):
    if request.method == "POST":
        if 'sub4' in request.POST:
            color_name = request.POST.get('name4')
            if Tbl_Color.objects.filter(color_name=color_name).exists():
                messages.error(request, f"Color '{color_name}' already exists.")
            else:
                Tbl_Color.objects.create(color_name=color_name)
                messages.success(request, f"Color '{color_name}' added successfully.")
                
        elif 'sub2' in request.POST:
            company_name = request.POST.get('name2')
            if Tbl_Company.objects.filter(company_name=company_name).exists():
                messages.error(request, f"Company '{company_name}' already exists.")
            else:
                Tbl_Company.objects.create(company_name=company_name)
                messages.success(request, f"Company '{company_name}' added successfully.")
                
        elif 'sub3' in request.POST:
            model_name = request.POST.get('name3')
            if Tbl_Model.objects.filter(model_name=model_name).exists():
                messages.error(request, f"Model '{model_name}' already exists.")
            else:
                Tbl_Model.objects.create(model_name=model_name)
                messages.success(request, f"Model '{model_name}' added successfully.")
                
        elif 'sub5' in request.POST:
            vehicle_type_name = request.POST.get('name5')
            if VehicleType.objects.filter(name=vehicle_type_name).exists():
                messages.error(request, f"Vehicle Type '{vehicle_type_name}' already exists.")
            else:
                VehicleType.objects.create(name=vehicle_type_name)
                messages.success(request, f"Vehicle Type '{vehicle_type_name}' added successfully.")
        
    return redirect('adminadd_dtl')

@nocache
def adminprofile(request):
    return render(request, 'adminprofile.html')

def adminprofile(request):
    return render(request, 'adminprofile.html')

# def admincaradd_dtl(request):
#     return render(request, 'admincaradd_dtl.html')

def user_detail(request, user_id):
    user = get_object_or_404(User, id=user_id)
    return render(request, 'user_detail.html', {'user': user})

def admincaradd_dtl(request):
    companies = Tbl_Company.objects.all()
    models = Tbl_Model.objects.all()
    colors = Tbl_Color.objects.all()
    car_types = VehicleType.objects.all()

    if request.method == "POST":
        manufacturer_id = request.POST.get('manufacturer')
        model_id = request.POST.get('model')
        year = request.POST.get('year')
        price = request.POST.get('price')
        color_id = request.POST.get('color')
        fuel_type = request.POST.get('fuel_type')
        kilometers = request.POST.get('km')
        transmission = request.POST.get('transmission')
        condition = request.POST.get('condition')
        reg_number = request.POST.get('reg_number')
        insurance_validity = request.POST.get('insurance_validity')
        pollution_validity = request.POST.get('pollution_validity')
        tax_validity = request.POST.get('tax_validity')
        car_type_id = request.POST.get('car_type')
        image = request.FILES.get('image')

        # Save the data to the database
        car_details = UserCarDetails(
            manufacturer_id=manufacturer_id,
            model_name_id=model_id,
            year=year,
            price=price,
            color_id=color_id,
            fuel_type=fuel_type,
            kilometers=kilometers,
            transmission=transmission,
            condition=condition,
            reg_number=reg_number,
            insurance_validity=insurance_validity,
            pollution_validity=pollution_validity,
            tax_validity=tax_validity,
            car_type_id=car_type_id,
            image=image
        )
        car_details.save()
        messages.success(request, 'Car details added successfully!')
        return redirect('admincaradd_dtl')  # Replace with your redirect URL

    return render(request, 'admincaradd_dtl.html', {
        'manufacturers': companies,
        'models': models,
        'colors': colors,
        'car_types': car_types,
    })
