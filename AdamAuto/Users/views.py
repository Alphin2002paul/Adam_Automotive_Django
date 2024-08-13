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
import re

users = get_user_model()

class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return str(user.pk) + str(timestamp)

token_generator = CustomTokenGenerator()

def generate_otp():
    return random.randint(100000, 999999)

def login_view(request):
    user = request.user
    if user.is_authenticated:
        if user.status != 1:
            messages.error(request, 'Your account is not active.')
            logout(request)  # Log out the user
            return redirect('login')
        if user.user_type == "admin":
            return redirect('adminindex')
        if user.user_type == "customer":
            return redirect('main')
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = authenticate(request, email=email, password=password)

        if user is not None and user.status == "1":
            auth_login(request, user)
            if user.user_type == "admin":
                return redirect('adminindex')
            if user.user_type == "customer":
                return redirect('main')
        else:
            messages.error(request, 'Invalid email or password or inactive account.')
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
        user_type = request.POST['user_type']
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
                'user_type': user_type,
            }

            # Send OTP to user's email
            send_mail(
                'Your OTP for logging in',
                f'Your OTP is {otp}',
                'your-email@gmail.com',
                [email],
                fail_silently=False,
            )

            
            return redirect(reverse('verify_otp'))
            
        
        except Exception as e:
            messages.error(request, f"Error creating account: {str(e)}")
            return redirect('register')

    return render(request, 'register.html')

from django.http import JsonResponse

def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST['otp']
        session_otp = request.session.get('otp')
        user_details = request.session.get('user_details')

        if not user_details or not session_otp:
            return JsonResponse({"success": False, "message": "Session expired or invalid data. Please try registering again."})

        if otp == str(session_otp):
            try:
                user = users.objects.create(
                    first_name=user_details['first_name'],
                    last_name=user_details['last_name'],
                    email=user_details['email'],
                    username=user_details['username'],
                    Phone_number=user_details['phone'],
                    user_type=user_details['user_type'],
                    status=1
                )
                user.set_password(user_details['password'])
                user.save()

                # Clear session data
                del request.session['otp']
                del request.session['user_details']

                return JsonResponse({"success": True, "message": "Account created successfully!"})
            except Exception as e:
                return JsonResponse({"success": False, "message": f"Error saving user: {str(e)}"})
        else:
            return JsonResponse({"success": False, "message": "Invalid OTP. Please try again."})

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
            return redirect('login')
        
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
@nocache
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

from django.http import JsonResponse

def add_details(request):
    if request.method == "POST":
        color_name = request.POST.get('name4')
        company_name = request.POST.get('name2')
        model_name = request.POST.get('name3')
        vehicle_type = request.POST.get('name5')

        response = {}

        if color_name:
            if not Tbl_Color.objects.filter(color_name=color_name).exists():
                Tbl_Color.objects.create(color_name=color_name)
                response['color'] = color_name

        if company_name:
            if not Tbl_Company.objects.filter(company_name=company_name).exists():
                Tbl_Company.objects.create(company_name=company_name)
                response['company'] = company_name

        if model_name:
            if not Tbl_Model.objects.filter(model_name=model_name).exists():
                Tbl_Model.objects.create(model_name=model_name)
                response['model'] = model_name

        if vehicle_type:
            if not VehicleType.objects.filter(name=vehicle_type).exists():
                VehicleType.objects.create(name=vehicle_type)
                response['vehicle_type'] = vehicle_type

        return JsonResponse(response)

    return render(request, 'adminadd_dtl.html')
@nocache
def adminprofile(request):
    return render(request, 'adminprofile.html')

def adminprofile(request):
    return render(request, 'adminprofile.html')

def userdisplaycars_dtl(request):
    cars = UserCarDetails.objects.all()
    return render(request, 'userdisplaycars_dtl.html',{'cars': cars})



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
        owner_status = request.POST.get('owner_status')
        car_status = request.POST.get('car_status')
        car_cc = request.POST.get('car_cc')

        # Validations
        errors = []
        if not price.isdigit():
            errors.append("Price must be an integer.")
        if not (year.isdigit() and len(year) == 4):
            errors.append("Year must be a 4-digit integer.")
        if fuel_type not in ["Petrol", "Diesel", "Electric", "Hybrid"]:
            errors.append("Fuel type must be one of: Petrol, Diesel, Electric, Hybrid.")
        if not kilometers.isdigit():
            errors.append("Kilometers must be an integer.")
        if transmission not in ["Manual", "Automatic"]:
            errors.append("Transmission must be one of: Manual, Automatic.")
        # if not condition.isalnum() or len(condition.split()) < 15:
        #     errors.append("Condition must be at least 15 words long and contain only letters and numbers.")
        if not reg_number or not re.match(r'^[A-Z]{2}-\d{2}-[A-Z]-\d{4}$', reg_number):
            errors.append("Registration number must be in the format: 'AA-00-A-0000'.")
        if not owner_status.isdigit():
            errors.append("Owner status must be an integer.")
        if car_status not in ["Available", "Sold", "Pending"]:
            errors.append("Car status must be one of: Available, Sold, Pending.")
        if not car_cc.isdigit() or not (3 <= len(car_cc) <= 4):
            errors.append("Engine CC must be a 3 or 4-digit integer.")

        if errors:
            for error in errors:
                messages.error(request, error)
        else:
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
                image=image,
                owner_status=owner_status,
                car_status=car_status,
                car_cc=car_cc
            )
            car_details.save()
            messages.success(request, 'Car details added successfully!')
            return redirect('admincaradd_dtl')

    return render(request, 'admincaradd_dtl.html', {
        'manufacturers': companies,
        'models': models,
        'colors': colors,
        'car_types': car_types,
    })
    
    
    
# views.py
from django.shortcuts import get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import User

@csrf_exempt
def update_user_status(request, user_id):
    if request.method == "POST":
        user = get_object_or_404(User, id=user_id)
        status = request.POST.get("status")
        if status is not None:
            user.status = int(status)
            user.save()
            return JsonResponse({"success": True})
    return JsonResponse({"success": False}, status=400)

from django.shortcuts import render
from django.db.models import Q
from django.core.paginator import Paginator
from .models import UserCarDetails, Tbl_Company

def userdisplaycarnologin_dtl(request):
    # Fetch only available cars
    cars = UserCarDetails.objects.filter(car_status='Available')
    brands = Tbl_Company.objects.all()

    # Apply filters
    search_query = request.GET.get('search')
    brand = request.GET.get('brand')
    price_range = request.GET.get('price_range')
    year = request.GET.get('year')

    if search_query:
        cars = cars.filter(
            Q(manufacturer__company_name__icontains=search_query) |
            Q(model_name__model_name__icontains=search_query)
        )

    if brand:
        cars = cars.filter(manufacturer_id=brand)

    if price_range:
        if price_range == '5000000+':
            cars = cars.filter(price__gte=5000000)
        else:
            min_price, max_price = map(int, price_range.split('-'))
            cars = cars.filter(price__gte=min_price, price__lte=max_price)

    if year:
        cars = cars.filter(year__gte=int(year))

    no_cars = cars.count() == 0

    # Pagination
    paginator = Paginator(cars, 6)  # Show 6 cars per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'brands': brands,
        'no_cars': no_cars,
    }

    return render(request, 'userdisplaycarnologin_dtl.html', context)


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import UserCarDetails, LikedCar

@login_required
def toggle_like(request, car_id):
    car = get_object_or_404(UserCarDetails, id=car_id)
    liked_car, created = LikedCar.objects.get_or_create(user=request.user, car=car)
    
    if not created:
        liked_car.delete()
        is_liked = False
    else:
        is_liked = True
    
    return JsonResponse({'is_liked': is_liked})

from django.core.paginator import Paginator

@login_required
def userdisplaycars_dtl(request):
    cars = UserCarDetails.objects.all()
    paginator = Paginator(cars, 3)  # Show 3 cars per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    liked_cars = LikedCar.objects.filter(user=request.user).values_list('car_id', flat=True)
    return render(request, 'userdisplaycars_dtl.html', {'page_obj': page_obj, 'liked_cars': liked_cars})

@login_required
def liked_list(request):
    liked_cars = LikedCar.objects.filter(user=request.user).select_related('car')
    paginator = Paginator(liked_cars, 3)  # Show 3 cars per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'likedlist_dtl.html', {'page_obj': page_obj})

from django.db.models import Q
from django.core.paginator import Paginator
from .models import UserCarDetails, LikedCar, Tbl_Company
@login_required
def userdisplaycars_dtl(request):
    cars = UserCarDetails.objects.filter(car_status='Available')
    brands = Tbl_Company.objects.all()

    # Apply filters
    search_query = request.GET.get('search')
    brand = request.GET.get('brand')
    price_range = request.GET.get('price_range')
    year = request.GET.get('year')

    if search_query:
        cars = cars.filter(
            Q(manufacturer__company_name__icontains=search_query) |
            Q(model_name__model_name__icontains=search_query)
        )

    if brand:
        cars = cars.filter(manufacturer_id=brand)

    if price_range:
        if price_range == '5000000+':
            cars = cars.filter(price__gte=5000000)
        else:
            min_price, max_price = map(int, price_range.split('-'))
            cars = cars.filter(price__gte=min_price, price__lte=max_price)

    if year:
        cars = cars.filter(year__gte=int(year))

    # Check if there are any cars after filtering
    no_cars = cars.count() == 0

    # Pagination
    paginator = Paginator(cars, 6)  # Show 6 cars per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    liked_cars = LikedCar.objects.filter(user=request.user).values_list('car_id', flat=True)

    context = {
        'page_obj': page_obj,
        'liked_cars': liked_cars,
        'brands': brands,
        'no_cars': no_cars,
    }

    return render(request, 'userdisplaycars_dtl.html', context)
from django.core.paginator import Paginator

def edit_listing(request):
    cars = UserCarDetails.objects.all().order_by('-id')
    paginator = Paginator(cars, 3)  # Show 6 cars per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'edit_listing.html', {'cars': page_obj})
def edit_car(request, car_id):
    # Implement car editing logic here
    pass

from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
import json

@require_POST
@csrf_exempt
def toggle_car_status(request, car_id):
    try:
        car = UserCarDetails.objects.get(id=car_id)
        data = json.loads(request.body)
        action = data.get('action')

        if action == 'Delete Car':
            car.car_status = 'Pending'
        elif action == 'Republish':
            car.car_status = 'Available'
        else:
            return JsonResponse({'success': False, 'error': 'Invalid action'})

        car.save()
        return JsonResponse({'success': True, 'new_status': car.car_status})
    except UserCarDetails.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Car not found'})
    
def speccaredit_dtl(request):
    return render(request, 'speccaredit_dtl.html')

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import UserCarDetails, Tbl_Company,Tbl_Color,VehicleType

def speccaredit_dtl(request, car_id):
    car = get_object_or_404(UserCarDetails, id=car_id)
    manufacturers = Tbl_Company.objects.all()
    models = Tbl_Model.objects.all()  # Change this line
    colors = Tbl_Color.objects.all()
    car_types = VehicleType.objects.all()

    if request.method == 'POST':
        # Update car details
        car.manufacturer_id = request.POST.get('manufacturer')
        car.model_name_id = request.POST.get('model')  # Keep this as model_name_id
        car.year = request.POST.get('year')
        car.price = request.POST.get('price')
        car.color_id = request.POST.get('color')
        car.fuel_type = request.POST.get('fuel_type')
        car.kilometers = request.POST.get('km')
        car.transmission = request.POST.get('transmission')
        car.condition = request.POST.get('condition')
        car.registration_number = request.POST.get('reg_number')
        car.insurance_validity = request.POST.get('insurance_validity')
        car.pollution_validity = request.POST.get('pollution_validity')
        car.tax_validity = request.POST.get('tax_validity')
        car.car_type_id = request.POST.get('car_type')
        car.owner_status = request.POST.get('owner_status')
        car.car_status = request.POST.get('car_status')
        car.car_cc = request.POST.get('car_cc')

        if 'image' in request.FILES:
            car.image = request.FILES['image']

        try:
            car.save()
            messages.success(request, 'Car details updated successfully.')
            return redirect('edit_listing')
        except Exception as e:
            messages.error(request, f'Error updating car details: {str(e)}')

    context = {
        'car': car,
        'manufacturers': manufacturers,
        'models': models,
        'colors': colors,
        'car_types': car_types,
    }
    return render(request, 'speccaredit_dtl.html', context)

def morecar_dtl(request, car_id):
    car = get_object_or_404(UserCarDetails, id=car_id)
    car_images = UserCarDetails.objects.filter(id=car_id)
    context = {
        'car': car,
        'car_images': car_images,
    }
    return render(request, 'morecar_dtl.html', context)

from django.shortcuts import render
from .models import Tbl_Company, Tbl_Model, Tbl_Color, VehicleType

def category_edit(request):
    companies = Tbl_Company.objects.all()
    models = Tbl_Model.objects.all()
    colors = Tbl_Color.objects.all()
    car_types = VehicleType.objects.all()

    context = {
        'companies': companies,
        'models': models,
        'colors': colors,
        'car_types': car_types,
    }

    return render(request, 'category_edit.html', context)

from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from .models import Tbl_Company, Tbl_Model, Tbl_Color, VehicleType

@login_required
@require_POST
def delete_category(request):
    category_type = request.POST.get('type')
    category_id = request.POST.get('id')

    try:
        if category_type == 'company':
            Tbl_Company.objects.filter(id=category_id).delete()
        elif category_type == 'model':
            Tbl_Model.objects.filter(id=category_id).delete()
        elif category_type == 'color':
            Tbl_Color.objects.filter(id=category_id).delete()
        elif category_type == 'car_type':
            VehicleType.objects.filter(id=category_id).delete()
        else:
            return JsonResponse({'success': False, 'error': 'Invalid category type'})

        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})
    
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from .models import Tbl_Company, Tbl_Model, Tbl_Color, VehicleType

@csrf_exempt
@require_POST
def update_category(request):
    category_type = request.POST.get('type')
    category_id = request.POST.get('id')
    new_name = request.POST.get('new_name')

    try:
        if category_type == 'company':
            category = Tbl_Company.objects.get(id=category_id)
            category.company_name = new_name
        elif category_type == 'model':
            category = Tbl_Model.objects.get(id=category_id)
            category.model_name = new_name
        elif category_type == 'color':
            category = Tbl_Color.objects.get(id=category_id)
            category.color_name = new_name
        elif category_type == 'car_type':
            category = VehicleType.objects.get(id=category_id)
            category.name = new_name
        else:
            return JsonResponse({'success': False, 'error': 'Invalid category type'})

        category.save()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})
@csrf_exempt
def update_user_status(request, user_id):
    if request.method == "POST":
        user = get_object_or_404(User, id=user_id)
        status = request.POST.get("status")
        reason = request.POST.get("reason", "")
        if status is not None:
            user.status = int(status)
            if int(status) == 0:
                user.description = reason
            user.save()
            return JsonResponse({"success": True})
    return JsonResponse({"success": False}, status=400)

from django.core.mail import send_mail
from django.conf import settings

@csrf_exempt
def send_disable_email(request, user_id):
    if request.method == "POST":
        user = get_object_or_404(User, id=user_id)
        reason = request.POST.get("reason", "")
        
        subject = 'Your Adam Automotive Account Has Been Disabled'
        message = f"""
        Dear {user.first_name} {user.last_name},

        We regret to inform you that your Adam Automotive account has been disabled.

        Reason: {reason}

        If you have any questions or concerns, please contact our support team.

        Best regards,
        Adam Automotive Team
        """
        
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]
        
        try:
            send_mail(subject, message, from_email, recipient_list)
            return JsonResponse({"success": True})
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return JsonResponse({"success": False}, status=500)
    
    return JsonResponse({"success": False}, status=400)