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
import sys
import os
from .ml import make_prediction

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
        user = request.user
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.Phone_number = request.POST.get('Phone_number')
        user.street_address = request.POST.get('address')  # Changed from 'street_address' to 'address'
        user.city = request.POST.get('city')
        user.state = request.POST.get('state')
        user.zipcode = request.POST.get('zipcode')
        
        if 'photo' in request.FILES:
            user.profile_picture = request.FILES['photo']
        
        user.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('account_edit')
    
    return render(request, 'account_edit.html', {'user': request.user})
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

from django.core.files.uploadedfile import InMemoryUploadedFile
from .models import CarImage

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
        images = request.FILES.getlist('images')
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
        if not reg_number or not re.match(r'^[A-Z]{2}-\d{2}-[A-Z]-\d{4}$', reg_number):
            errors.append("Registration number must be in the format: 'AA-00-A-0000'.")
        if not owner_status.isdigit():
            errors.append("Owner status must be an integer.")
        if car_status not in ["Available", "Sold", "Pending"]:
            errors.append("Car status must be one of: Available, Sold, Pending.")
        if not car_cc.isdigit() or not (3 <= len(car_cc) <= 4):
            errors.append("Engine CC must be a 3 or 4-digit integer.")
        if len(images) > 5:
            errors.append("You can upload a maximum of 5 images.")

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
                owner_status=owner_status,
                car_status=car_status,
                car_cc=car_cc
            )
            car_details.save()

            # Save multiple images
            for image in images[:5]:  # Limit to first 5 images
                if isinstance(image, InMemoryUploadedFile):
                    CarImage.objects.create(car=car_details, image=image)

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
    
# def speccaredit_dtl(request):
#     return render(request, 'speccaredit_dtl.html')

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.exceptions import ValidationError
from .models import UserCarDetails, CarImage, Tbl_Company, Tbl_Model, Tbl_Color, VehicleType
from django.core.files.storage import default_storage
import os

def speccaredit_dtl(request, car_id):
    car = get_object_or_404(UserCarDetails, id=car_id)
    manufacturers = Tbl_Company.objects.all()
    models = Tbl_Model.objects.all()
    colors = Tbl_Color.objects.all()
    car_types = VehicleType.objects.all()

    if request.method == "POST":
        try:
            # Update car details
            car.manufacturer_id = request.POST.get('manufacturer')
            car.model_name_id = request.POST.get('model')
            car.year = request.POST.get('year')
            car.price = request.POST.get('price')
            car.color_id = request.POST.get('color')
            car.fuel_type = request.POST.get('fuel_type')
            car.kilometers = request.POST.get('km')
            car.transmission = request.POST.get('transmission')
            car.condition = request.POST.get('condition')
            car.reg_number = request.POST.get('reg_number')
            car.insurance_validity = request.POST.get('insurance_validity')
            car.pollution_validity = request.POST.get('pollution_validity')
            car.tax_validity = request.POST.get('tax_validity')
            car.car_type_id = request.POST.get('car_type')
            car.owner_status = request.POST.get('owner_status')
            car.car_status = request.POST.get('car_status')
            car.car_cc = request.POST.get('car_cc')

            car.full_clean()  # Validate the model
            car.save()

            # Handle image updates
            new_images = request.FILES.getlist('images')
            existing_images = CarImage.objects.filter(car=car)

            if new_images:
                # Delete old images
                for old_image in existing_images:
                    if old_image.image:
                        if os.path.isfile(old_image.image.path):
                            os.remove(old_image.image.path)
                    old_image.delete()

                # Add new images
                for image in new_images[:5]:  # Limit to first 5 images
                    CarImage.objects.create(car=car, image=image)

            messages.success(request, 'Car details updated successfully.')
            return redirect('edit_listing')

        except ValidationError as e:
            messages.error(request, f'Validation error: {e}')
        except ValueError as e:
            messages.error(request, f'Invalid value: {e}')
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
    car_images = car.images.all()  # Assuming you have a related_name='images' in your CarImage model
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

from django.http import JsonResponse
from django.views.decorators.http import require_GET

@require_GET
def get_disable_reason(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        return JsonResponse({'success': True, 'reason': user.description})
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'})
from django.shortcuts import render, get_object_or_404
from .models import UserCarDetails, CarImage

def car_detail(request, car_id):
    car = get_object_or_404(UserCarDetails, id=car_id)
    car_images = CarImage.objects.filter(car=car)
    context = {
        'car': car,
        'car_images': car_images,
    }
    return render(request, 'car_detail.html', context)

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Service
from datetime import datetime

@login_required
def bookservice_dtl(request):
    if request.method == 'POST':
        print("Form submitted")  # Debugging line
        manufacturer = request.POST.get('manufacturer')
        model = request.POST.get('model')
        transmission = request.POST.get('transmission')
        fuel = request.POST.get('fuel')
        year = request.POST.get('year')
        problem = request.POST.get('problem')
        service_date_str = request.POST.get('serviceDate')

        # Convert service_date_str to a date object
        service_date = datetime.strptime(service_date_str, '%Y-%m-%d').date()

        # Create a new Service instance
        service = Service(
            manufacturer=manufacturer,
            model=model,
            transmission=transmission,
            fuel=fuel,
            year=int(year),  # Ensure year is an integer
            problem=problem,
            service_date=service_date,
            user=request.user  # Set the user who is booking the service
        )

        try:
            service.full_clean()  # Validate the model before saving
            service.save()  # Save the service details to the database
            print("Service saved successfully.")
            return redirect('main')  # Redirect to the main page after saving
        except ValidationError as e:
            print(f"Validation error: {e}")  # Print validation errors
        except Exception as e:
            print(f"Error saving service: {str(e)}")  # Print any other errors

    # Handle GET request
    return render(request, 'bookservice_dtl.html')

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import SellCar, SellCarImage
from django.contrib import messages

@login_required
def sellcar_dtl(request):
    if request.method == 'POST':
        # Create a new SellCar instance
        sell_car = SellCar(
            user=request.user,
            manufacturer=request.POST['manufacturer'],
            model=request.POST['model'],
            year=request.POST['year'],
            price=request.POST['price'],
            color=request.POST['color'],
            fuel_type=request.POST['fuel_type'],
            kilometers=request.POST['kilometers'],
            transmission=request.POST['transmission'],
            condition=request.POST['condition'],
            reg_number=request.POST['reg_number'],
            insurance_validity=request.POST['insurance_validity'],
            pollution_validity=request.POST['pollution_validity'],
            tax_validity=request.POST['tax_validity'],
            car_type=request.POST['car_type'],
            owner_status=request.POST['owner_status'],
            car_cc=request.POST['car_cc'],
        )
        sell_car.save()

        # Handle image uploads
        images = request.FILES.getlist('images')
        for image in images:
            SellCarImage.objects.create(sell_car=sell_car, image=image)

        messages.success(request, 'Your car details have been submitted successfully.')
        return redirect('main')

    return render(request, 'sellcar_dtl.html')

from django.shortcuts import render
from .models import Service

from django.shortcuts import render
from .models import Service

# views.py
from django.shortcuts import render
from .models import Service

def service_request_view(request):
    # Filter services with status 'Pending'
    services = Service.objects.filter(status='Pending')
    return render(request, 'service_request_view.html', {'services': services}) # Ensure the template name is correct

@login_required
def get_service_details(request, service_id):
    service = get_object_or_404(Service, id=service_id)
    data = {
        'manufacturer': service.manufacturer,
        'model': service.model,
        'service_date': service.service_date,
        'user': {
            'username': service.user.username,
            'email': service.user.email,
            'phone_number': service.user.Phone_number,
        },
        'transmission': service.transmission,
        'fuel': service.fuel,
        'year': service.year,
        'problem': service.problem,
    }
    return JsonResponse(data)

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import UserCarDetails, User

def get_user_details(request, car_id):
    car = get_object_or_404(SellCar, id=car_id)
    user = car.user  # Assuming there's a user field in UserCarDetails model
    
    if user:
        data = {
            'success': True,
            'user': {
                'name': f"{user.first_name} {user.last_name}",
                'username': user.username,
                'email': user.email,
                'phone_number': user.Phone_number,
            }
        }
    else:
        data = {'success': False, 'error': 'User not found'}
    
    return JsonResponse(data)

# views.py
from django.core.mail import send_mail
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Service
import json

@csrf_exempt
def approve_service(request, service_id):
    if request.method == 'POST':
        data = json.loads(request.body)
        time_slot = data.get('timeSlot')  # Ensure this is being sent correctly
        new_date = data.get('suggestedDate')  # This will be the new date or the original suggested date

        try:
            service = Service.objects.get(id=service_id)
            # Update the service details
            service.service_date = new_date
            service.slot = time_slot  # Ensure 'slot' is the correct field name in your model
            service.status = 'Approved'  # Update status to Approved
            service.save()  # Save the updated service

            # Prepare email content
            user_name = f"{service.user.first_name} {service.user.last_name}"  # Assuming user model has first_name and last_name
            email_body = f"""
            Dear {user_name},

            We are pleased to inform you that your request for servicing of the vehicle {service.manufacturer} {service.model} has been approved.

            Date: {service.service_date}
            Time Slot: {service.slot}  # Ensure this is the correct attribute
            If you have any questions or concerns, please contact our support team.

            Best regards,
            Adam Automotive Team
            """

            # Send email notification
            send_mail(
                'Service Request Approved',
                email_body,
                'adamautomotive3@gmail.com',
                [service.user.email],  # Assuming the user model has an email field
                fail_silently=False,
            )
            return JsonResponse({'success': True})
        except Service.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Service not found.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})


@csrf_exempt
def deny_service(request, service_id):
    if request.method == 'POST':
        data = json.loads(request.body)
        reason = data.get('reason')
        manufacturer = data.get('manufacturer')
        model = data.get('model')

        try:
            service = Service.objects.get(id=service_id)
            service.status = 'Denied'  # Change status to Denied
            service.save()  # Save the updated status

            user_name = f"{service.user.first_name} {service.user.last_name}"  # Assuming user model has first_name and last_name

            # Format the email body
            email_body = f"""
            Dear {user_name},

            We regret to inform you that your service request for the {manufacturer} {model} has been rejected.

            Reason: {reason}

            If you have any questions or concerns, please contact our support team.

            Best regards,
            Adam Automotive Team
            """

            # Send email notification
            send_mail(
                'Service Request Denied',
                email_body,
                'adamautomotive3@gmail.com',
                [service.user.email],  # Assuming the user model has an email field
                fail_silently=False,
            )
            return JsonResponse({'success': True})
        except Service.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Service not found.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
        
@login_required
def request_dtl(request):
    # Fetch services for the logged-in user, excluding those with status 'Deleted'
    services = Service.objects.filter(user=request.user).exclude(status='Deleted')
    return render(request, 'request_dtl.html', {'services': services})

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Service

@csrf_exempt
def update_service(request, service_id):
    if request.method == 'POST':
        data = json.loads(request.body)
        try:
            service = Service.objects.get(id=service_id)
            service.manufacturer = data['manufacturer']
            service.model = data['model']
            service.service_date = data['service_date']
            service.transmission = data['transmission']  # Update transmission
            service.fuel = data['fuel']                  # Update fuel
            service.year = data['year']                  # Update year
            service.problem = data['problem']            # Update problem
            service.save()
            return JsonResponse({'success': True})
        except Service.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Service not found.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from .models import Service

@csrf_exempt
def delete_service(request, service_id):
    if request.method == 'POST':
        try:
            service = Service.objects.get(id=service_id)
            service.status = 'Deleted'  # Change status to Deleted
            service.save()  # Save the updated status
            return JsonResponse({'success': True})
        except Service.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Service not found.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
        
from django.http import JsonResponse
from .models import SellCar

def check_registration_number(request):
    reg_number = request.GET.get('reg_number', '')
    exists = SellCar.objects.filter(reg_number=reg_number).exists()
    return JsonResponse({'exists': exists})

from django.shortcuts import render
from django.core.paginator import Paginator
from .models import SellCar, CarImage

from django.shortcuts import render
from django.core.paginator import Paginator
from .models import SellCar, CarImage

def salereq_dsply(request):
    # Filter cars with 'pending' status
    pending_cars = SellCar.objects.filter(status='pending').order_by('-created_at')
    
    # Add images to each car
    for car in pending_cars:
        car.image_list = CarImage.objects.filter(car=car.id)
    
    # Pagination
    paginator = Paginator(pending_cars, 3)  # Show 9 cars per page
    page_number = request.GET.get('page')
    sell_cars = paginator.get_page(page_number)
    
    context = {
        'sell_cars': sell_cars,
    }
    return render(request, 'salereq_dsply.html', context)

from django.shortcuts import render, get_object_or_404
from .models import SellCar, SellCarImage

def salemore_dtl(request, car_id):
    car = get_object_or_404(SellCar, id=car_id)
    images = SellCarImage.objects.filter(sell_car=car)
    
    # Create a dictionary of car details, only including fields that exist
    car_details = {
        'Manufacturer': car.manufacturer,
        'Model': car.model,
        'Year': car.year,
        'Price': car.price,
        'Fuel Type': car.fuel_type,
        'Transmission': car.transmission,
        'Color': car.color,
        'Registration Number': car.reg_number,
        'Number of Owners': car.owner_status,
        'Insurance Valid Until': car.insurance_validity,
        'Description': car.condition,
        'Status': car.status,
        'Created At': car.created_at,
    }

    # Only add the 'User' field if it exists and is not None
    if hasattr(car, 'user') and car.user:
        car_details['User'] = car.user.username

    context = {
        'car': car,
        'images': images,
        'car_details': car_details,
    }
    return render(request, 'salemore_dtl.html', context)



from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.http import JsonResponse

User = get_user_model()


from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404
from .models import SellCar
import json

@require_POST
def cancel_car_listing(request, car_id):
    try:
        data = json.loads(request.body)
        reason = data.get('reason')
        
        car = get_object_or_404(SellCar, id=car_id)
        car.car_status = "Denied"
        car.denial_reason = reason
        car.save()
        
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})
    
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.conf import settings
from .models import SellCar
import json

@require_POST
def cancel_car_listing(request, car_id):
    try:
        data = json.loads(request.body)
        reason = data.get('reason')
        
        car = get_object_or_404(SellCar, id=car_id)
        car.status = "Denied"
        car.denial_reason = reason
        car.save()
        
        # Send email to the user
        subject = f"Your car listing for {car.manufacturer} {car.model} has been cancelled"
        message = f"""
        Dear {car.user.first_name},

        We regret to inform you that your car listing for {car.manufacturer} {car.model} has been cancelled.

        Reason for cancellation: {reason}

        If you have any questions, please don't hesitate to contact us.

        Best regards,
        Adam Automotive Team
        """
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [car.user.email]
        
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})
    
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.conf import settings
from .models import SellCar
import json

@require_POST
@csrf_exempt
def approve_car_listing(request, car_id):
    try:
        data = json.loads(request.body)
        remarks = data.get('remarks')
        
        car = SellCar.objects.get(id=car_id)
        car.status = 'Approved'
        car.admin_remarks = remarks
        car.save()
        
        # Send email to the user
        subject = 'Your Car Listing Has Been Approved'
        message = f"""
        Dear {car.user.first_name},

        Your request to sell your {car.manufacturer} {car.model} has been approved.

        Admin remarks: {remarks}

        Thank you for choosing Adam Automotive.

        Best regards,
        Adam Automotive Team
        """
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [car.user.email]
        
        send_mail(subject, message, from_email, recipient_list)
        
        return JsonResponse({'success': True})
    except SellCar.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Car not found'}, status=404)
    except Exception as e:
        print(f"Error in approve_car_listing: {str(e)}")  # Log the error
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
    

from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from .models import Feedback
from django.core.exceptions import ValidationError
import os
import csv

def feedback_dtl(request):
    if request.method == 'POST':
        # Get form data
        manufacturer_name = request.POST.get('manufacturer_name')
        model_name = request.POST.get('model_name')
        year = request.POST.get('year')
        description = request.POST.get('description')
        
        # Get ratings
        ratings = {}
        for rating in ['comfort', 'performance', 'fuel_efficiency', 'safety', 'technology']:
            ratings[rating] = request.POST.get(f'{rating}_rating')

        try:
            # Save to database
            feedback = Feedback(
                user=request.user,
                manufacturer_name=manufacturer_name,
                model_name=model_name,
                year=year,
                comfort_rating=ratings['comfort'],
                performance_rating=ratings['performance'],
                fuel_efficiency_rating=ratings['fuel_efficiency'],
                safety_rating=ratings['safety'],
                technology_rating=ratings['technology'],
                description=description,
            )
            feedback.full_clean()  # Validate the model
            feedback.save()

            # Prepare data for CSV
            csv_data = [manufacturer_name, model_name, year, description] + list(ratings.values())

            # Save to CSV
            csv_file_path = os.path.join(settings.BASE_DIR, 'Users', 'car_reviews_with_feedback.csv')

            print(f"Attempting to open file at: {csv_file_path}")  # Debugging line

            # Check if the directory exists, if not, create it
            os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)

            file_exists = os.path.isfile(csv_file_path)

            with open(csv_file_path, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                if not file_exists:
                    writer.writerow(['manufacturer', 'model', 'year', 'description', 'comfort', 'performance', 'fuel_efficiency', 'safety', 'technology'])
                writer.writerow(csv_data)

            messages.success(request, 'Feedback submitted successfully!')
            return redirect('feedback_dtl')
        
        except Exception as e:
            print(f"Error details: {str(e)}")  # Add this line for more detailed error information
            messages.error(request, f'Error submitting feedback: {str(e)}')

    rating_list = ['comfort', 'performance', 'fuel_efficiency', 'safety', 'technology']
    return render(request, 'feedback_dtl.html', {'rating_list': rating_list})




from django.db.models import Avg
from django.http import JsonResponse
from .models import UserCarDetails, Feedback
from .ml import make_prediction
import traceback

users = get_user_model()

class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return str(user.pk) + str(timestamp)

token_generator = CustomTokenGenerator()

def get_predictions(request, car_id):
	try:
		car = UserCarDetails.objects.get(id=car_id)
		
		# Get feedback data for this specific car model and year
		feedback_data = Feedback.objects.filter(
			manufacturer_name=car.manufacturer.company_name,
			model_name=car.model_name.model_name,
			year=car.year
		)
		
		# Calculate average ratings
		avg_comfort = feedback_data.aggregate(Avg('comfort_rating'))['comfort_rating__avg'] or 0
		avg_performance = feedback_data.aggregate(Avg('performance_rating'))['performance_rating__avg'] or 0
		avg_fuel_efficiency = feedback_data.aggregate(Avg('fuel_efficiency_rating'))['fuel_efficiency_rating__avg'] or 0
		avg_safety = feedback_data.aggregate(Avg('safety_rating'))['safety_rating__avg'] or 0
		avg_technology = feedback_data.aggregate(Avg('technology_rating'))['technology_rating__avg'] or 0

		# Calculate overall average rating
		overall_avg_rating = (avg_comfort + avg_performance + avg_fuel_efficiency + avg_safety + avg_technology) / 5

		try:
			description = make_prediction(
				str(car.manufacturer.company_name),
				str(car.model_name.model_name),
				int(car.year),
				float(avg_comfort),
				float(avg_performance),
				float(avg_fuel_efficiency),
				float(avg_safety),
				float(avg_technology)
			)
		except Exception as e:
			print(f"Error making prediction: {str(e)}")
			description = "No prediction available."  # Default value if prediction fails

		predictions_html = f"""
		<h4>{car.manufacturer.company_name} {car.model_name.model_name} ({car.year})</h4>
		<p><strong>Overall Average Rating:</strong> {overall_avg_rating:.1f}/10</p>
		<hr>
		<h5>Average Ratings:</h5>
		<ul>
			<li>Comfort: {avg_comfort:.1f}/10</li>
			<li>Performance: {avg_performance:.1f}/10</li>
			<li>Fuel Efficiency: {avg_fuel_efficiency:.1f}/10</li>
			<li>Safety: {avg_safety:.1f}/10</li>
			<li>Technology: {avg_technology:.1f}/10</li>
		</ul>
		<hr>
		<h5>Recommendation:</h5>
		<p>{description}</p>
		"""

		return JsonResponse({
			'predictions_html': predictions_html,
			'average_rating': overall_avg_rating
		})

	except UserCarDetails.DoesNotExist:
		return JsonResponse({'error': 'Car not found'}, status=404)
	except Exception as e:
		print(f"Error in get_predictions: {str(e)}")
		print(traceback.format_exc())
		return JsonResponse({'error': 'An error occurred'}, status=500)


from django.http import JsonResponse
from django.views.decorators.http import require_POST

from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404
from .models import UserCarDetails, CarPurchase
from django.db import transaction

@require_POST
def process_payment(request):
    try:
        with transaction.atomic():
            # Extract data from request
            payment_id = request.POST.get('payment_id')
            car_id = request.POST.get('car_id')
            delivery_option = request.POST.get('delivery_option', 'showroom')  # Default to 'showroom' if not provided
            street = request.POST.get('street', '')
            city = request.POST.get('city', '')
            state = request.POST.get('state', '')
            pincode = request.POST.get('pincode', '')

            # Get the car object
            car = get_object_or_404(UserCarDetails, id=car_id)

            # Create a new CarPurchase instance
            purchase = CarPurchase(
                user=request.user,
                car=car,
                amount=car.price,
                delivery_option=delivery_option,
                street=street,
                city=city,
                state=state,
                pincode=pincode,
                payment_id=payment_id
            )
            purchase.save()

            # Update the car status to 'Sold'
            car.car_status = 'Sold'
            car.save()

        # Return success response
        return JsonResponse({'status': 'success'})
    except Exception as e:
        # Log the error for debugging
        print(f"Error processing payment: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from .models import TestDriveBooking, UserCarDetails
from django.core.exceptions import ValidationError
from django.db import IntegrityError

@require_POST
def book_test_drive(request):
    car_id = request.POST.get('car_id')
    date = request.POST.get('date')
    time = request.POST.get('time')

    try:
        car = UserCarDetails.objects.get(id=car_id)
        booking = TestDriveBooking(
            user=request.user,
            car=car,
            date=date,
            time=time
        )
        booking.save()
        return JsonResponse({'status': 'success', 'message': 'Test drive booked successfully'})
    except ValidationError as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except IntegrityError:
        return JsonResponse({'status': 'error', 'message': 'This time slot is no longer available'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

@require_GET
def get_available_slots(request):
    car_id = request.GET.get('car_id')
    date = request.GET.get('date')

    all_slots = [
        "9:00am - 10:00am", "10:00am - 11:00am", "11:00am - 12:00pm",
        "12:00pm - 1:00pm", "2:00pm - 3:00pm", "3:00pm - 4:00pm", "4:00pm - 5:00pm"
    ]

    booked_slots = TestDriveBooking.objects.filter(car_id=car_id, date=date).values_list('time', flat=True)
    available_slots = [slot for slot in all_slots if slot not in booked_slots]

    return JsonResponse({'available_slots': available_slots})

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import TestDriveBooking

def admintestdrive(request):
    testdrive_bookings = TestDriveBooking.objects.all()
    context = {
        'testdrive_bookings': testdrive_bookings
    }
    return render(request, 'admintestdrive.html', context)

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from .models import TestDriveBooking, UserCarDetails
import json
import logging

logger = logging.getLogger(__name__)

User = get_user_model()

def admintestdrive(request):
    # Filter test drive bookings to only show 'Pending' status
    testdrive_bookings = TestDriveBooking.objects.filter(status='Pending').select_related(
        'car__manufacturer', 
        'car__model_name', 
        'car__color', 
        'user'
    ).all()
    return render(request, 'admintestdrive.html', {'testdrive_bookings': testdrive_bookings})

@csrf_exempt
def approve_test_drive(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            booking_id = data.get('booking_id')
            logger.info(f"Received approval request for booking ID: {booking_id}")
            
            booking = TestDriveBooking.objects.get(id=booking_id)
            
            # Only change the status if it's currently 'Pending'
            if booking.status == 'pending':
                booking.status = 'Approved'
                booking.save()
                logger.info(f"Booking {booking_id} status updated to Approved")

                # Send email
                subject = 'Test Drive Request Approved'
                message = f"""
                Dear {booking.user.first_name},

                Your request for a test drive has been approved.

                Details:
                Date: {booking.date}
                Time: {booking.time}
                Vehicle: {booking.car.manufacturer} {booking.car.model_name}

                Thank you for choosing Adam Automotive.

                Best regards,
                Adam Automotive Team
                """
                from_email = settings.EMAIL_HOST_USER
                recipient_list = [booking.user.email]

                send_mail(subject, message, from_email, recipient_list)
                logger.info(f"Approval email sent to {booking.user.email}")

                return JsonResponse({'success': True})
            else:
                logger.warning(f"Booking {booking_id} is not in Pending status")
                return JsonResponse({'success': False, 'error': 'Booking is not in Pending status'})

        except TestDriveBooking.DoesNotExist:
            logger.error(f"Booking not found: {booking_id}")
            return JsonResponse({'success': False, 'error': 'Booking not found'})
        except json.JSONDecodeError:
            logger.error("Invalid JSON in request body")
            return JsonResponse({'success': False, 'error': 'Invalid JSON in request body'})
        except Exception as e:
            logger.exception("Error in approve_test_drive view")
            return JsonResponse({'success': False, 'error': str(e)})

    logger.warning("Invalid request method for approve_test_drive")
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

def get_test_drive_user_details(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'email': user.email,
            'phone_number': user.Phone_number,
        }
        return JsonResponse(data)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    
def mybookings(request):
    purchases = CarPurchase.objects.filter(user=request.user)

    return render(request, 'mybookings.html', {'purchases': purchases})



