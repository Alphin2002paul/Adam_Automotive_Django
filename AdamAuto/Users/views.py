from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from django.core.mail import send_mail
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login,logout,get_user_model
from django.contrib.auth import get_backends

from .models import User
import random
users=get_user_model()
class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return str(user.pk) + str(timestamp)

token_generator = CustomTokenGenerator()


def login_view(request):
    user=request.user
    if user.is_authenticated:
        return render(request, 'main.html')
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        try:
            user = users.objects.get(username=username, password=password)
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return render(request, 'main.html')
        except users.DoesNotExist:
            return HttpResponse("Invalid username or password.")
    
    return render(request, 'login.html')

def index(request):
    return render(request, 'index.html')

def forgetpass(request):
    return render(request, 'forgetpass.html')

def generate_otp():
    return random.randint(100000, 999999)

# Inside your register view function

def register(request):
    if request.method == 'POST':
        name = request.POST['name']
        phone = request.POST['phone']
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']

        try:
            otp = generate_otp()
            request.session['otp'] = otp
            request.session['user_details'] = {
                'name': name,
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
            
            # Redirect to verify_otp
            return redirect(reverse('verify_otp'))
        
        except Exception as e:
            messages.error(request, f"Error creating account: {str(e)}")
            return redirect('register')

    return render(request, 'register.html')


def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST['otp']
        print(otp)
        session_otp = request.session.get('otp')
        user_details = request.session.get('user_details')
        print(session_otp)
        if otp == str(session_otp):
            try:
                user = users.objects.create(
                    first_name=user_details['name'],
                    email=user_details['email'],
                    username=user_details['username'],
                    password=user_details['password'],
                    Phone_number=user_details['phone'],
                    user_type='customer'
                )
                messages.success(request, "OTP verified. You can now sign in.")
                return redirect('login')
            except Exception as e:
                messages.error(request, f"Error saving user: {str(e)}")
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request,'verify_otp.html')

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
            # Handle password reset form submission here
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
import os

from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from google.oauth2 import id_token
from google.auth.transport import requests
import jwt


def sign_in(request):
    return render(request, 'sign_in.html')


@csrf_exempt
def auth_receiver(request):
    """
    Google calls this URL after the user has signed in with their Google account.
    """
    token = request.POST['credential']

    try:
        user_data = id_token.verify_oauth2_token(
            token, requests.Request(), os.environ['GOOGLE_OAUTH_CLIENT_ID']
        )
    except ValueError:
        return HttpResponse(status=403)

    # In a real app, I'd also save any new user here to the database. See below for a real example I wrote for Photon Designer.
    # You could also authenticate the user here using the details from Google (https://docs.djangoproject.com/en/4.2/topics/auth/default/#how-to-log-a-user-in)
    request.session['user_data'] = user_data

    return redirect('sign_in')

def logout(request):
    # Clear session variables on logout
    request.session.flush()
    return redirect('index')


from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required

@login_required
def main_view(request):
    # Replace 'main.html' with your actual template name
    return render(request, 'main.html')

def auth_receiver(request):
    # Handle post-authentication redirect logic here if needed
    return redirect('main')
