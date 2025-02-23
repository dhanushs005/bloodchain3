import random
import os
import string
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
from django.core.exceptions import ValidationError
from .forms import UserForm, EmergencyForm, ReportForm, LoginForm, SignupForm
from pymongo import MongoClient, errors
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB connection setup
MONGO_URI = "mongodb+srv://Dhanush:2k22ca005@userdetails.mavp0oq.mongodb.net/?retryWrites=true&w=majority&appName=userdetails"
DB_NAME = "Users"
USER_COLLECTION = "User"
EMERGENCY_COLLECTION = "emergency"
REPORTS_COLLECTION = "reports"
LOGS_COLLECTION = "logs"

# Initialize MongoDB client with retry logic
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]
    # Ensure indexes for performance
    db[USER_COLLECTION].create_index([("user_id", 1), ("mobile", 1)])
    db[LOGS_COLLECTION].create_index([("user_id", 1), ("username", 1)])
    db[EMERGENCY_COLLECTION].create_index([("pmobile", 1)])
    db[REPORTS_COLLECTION].create_index([("mobile", 1)])
    logger.info("MongoDB connection established successfully.")
except errors.ConnectionError as e:
    logger.error(f"MongoDB connection failed: {str(e)}")
    raise Exception("Database connection failed. Please check your MongoDB URI.")

# Decorator to check user authentication
def login_required(view_func):
    def wrapper(request, *args, **kwargs):
        user_id = request.COOKIES.get("user_id")
        if not user_id:
            messages.error(request, "Please log in to access this page.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

# Utility function to generate session token
def generate_session_token(length=16):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))

# Home view
def home(request):
    return render(request, 'Main/home.html')

# Donate view
@login_required
def donate(request):
    form = UserForm()
    return render(request, 'Main/donate.html', {'UserForm': form})

# Report view
@login_required
def report(request):
    form = ReportForm()
    return render(request, 'Main/report.html', {'ReportForm': form})

# Emergency view
@login_required
def emerg(request):
    form = EmergencyForm()
    return render(request, 'Main/emergency.html', {'EmergencyForm': form})

# Login view
def login(request):
    if request.method == 'GET':
        lform = LoginForm()
        return render(request, 'Main/profile-login.html', {'form': lform})
    
    if request.method == 'POST':
        return login_user(request)

# Signup view
def signup(request):
    if request.method == 'GET':
        sform = SignupForm()
        return render(request, 'Main/profile-signup.html', {'form': sform})
    
    if request.method == 'POST':
        return save_logs(request)

# Profile view
@login_required
def profile(request):
    user_id = request.COOKIES.get("user_id")
    
    try:
        # Fetch user details from LOGS_COLLECTION
        user = db[LOGS_COLLECTION].find_one({"user_id": user_id}, {"_id": 0, "username": 1})
        if not user:
            messages.error(request, "User not found. Please log in again.")
            return redirect('login')

        username = user.get("username")
        password = "Password is secured"  # Placeholder for security

        # Fetch blood donation details from USER_COLLECTION
        blood_details = list(db[USER_COLLECTION].find({"user_id": user_id}, {"_id": 0, "name": 1, "mobile": 1, "blood_group": 1, "last_donated_date": 1, "district": 1}))

        blood_details_message = "No blood donation details available." if not blood_details else None

        return render(request, 'Main/profile.html', {
            'username': username,
            'password': password,
            'blood_details': blood_details,
            'blood_details_message': blood_details_message
        })
    except Exception as e:
        logger.error(f"Error fetching profile data: {str(e)}")
        messages.error(request, "An error occurred while loading your profile. Please try again.")
        return redirect('login')

# View donors and emergency data
@login_required
def view_donors(request):
    blood_group = request.GET.get('blood_group', '').strip()
    district = request.GET.get('district', '').strip()

    query = {}
    if blood_group:
        query['blood_group'] = blood_group
    if district:
        query['district'] = district

    try:
        donors = list(db[USER_COLLECTION].find(query, {"_id": 0}))
        emergency = list(db[EMERGENCY_COLLECTION].find({}, {"_id": 0}))

        # Add pagination for large datasets (optional, limit to 10 results per page)
        from django.core.paginator import Paginator
        paginator = Paginator(donors, 10)  # 10 donors per page
        page_number = request.GET.get('page', 1)
        donors_paginated = paginator.get_page(page_number)

        context = {
            'donors': donors_paginated,
            'emergency': emergency,
            'blood_group': blood_group,
            'district': district,
        }
        return render(request, 'Main/donors.html', context)
    except Exception as e:
        logger.error(f"Error fetching donors: {str(e)}")
        messages.error(request, "An error occurred while fetching donors. Please try again.")
        return render(request, 'Main/donors.html', {'donors': [], 'emergency': []})

# Save user details
@csrf_protect
@login_required
def save_user_details(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            mobile = cleaned_data['mobile']
            user_id = request.COOKIES.get("user_id")

            try:
                # Check for duplicate mobile number
                existing_user = db[USER_COLLECTION].find_one({"mobile": mobile})
                if existing_user:
                    messages.error(request, "Mobile number already exists!")
                    return redirect('donate')  # Redirect back to donate page with error

                # Validate mobile format (example: 10 digits)
                if not mobile.isdigit() or len(mobile) != 10:
                    messages.error(request, "Invalid mobile number format! Must be 10 digits.")
                    return redirect('donate')  # Redirect back to donate page with error

                # Save user details
                new_entry = {
                    "user_id": user_id,
                    "name": cleaned_data['name'],
                    "mobile": mobile,
                    "blood_group": cleaned_data['bg'],
                    "gender": cleaned_data['gender'],
                    "district": cleaned_data['dists'],
                    "last_donated_date": str(cleaned_data['last_date'])
                }
                db[USER_COLLECTION].insert_one(new_entry)
                logger.info(f"User details saved for user_id: {user_id}")
                messages.success(request, "User details saved successfully!")
                return redirect('profile')  # Redirect to profile page with success
            except Exception as e:
                logger.error(f"Error saving user details: {str(e)}")
                messages.error(request, f"An error occurred while saving user details: {str(e)}")
                return redirect('donate')  # Redirect back to donate page with error
        else:
            messages.error(request, "Invalid form data!")
            return redirect('donate')  # Redirect back to donate page with error
    return render(request, 'Main/donate.html', {'UserForm': UserForm()})

# Save emergency details
@csrf_protect
@login_required
def emergency_details(request):
    if request.method == 'POST':
        form = EmergencyForm(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            pmobile = cleaned_data['pmobile']

            try:
                # Check for duplicate mobile number in emergencies (optional, depending on requirements)
                existing_emergency = db[EMERGENCY_COLLECTION].find_one({"pmobile": pmobile})
                if existing_emergency:
                    messages.error(request, "Emergency already registered for this mobile number!")
                    return redirect('emergency')  # Redirect back to emergency page with error

                # Validate mobile format (example: 10 digits)
                if not pmobile.isdigit() or len(pmobile) != 10:
                    messages.error(request, "Invalid mobile number format! Must be 10 digits.")
                    return redirect('emergency')  # Redirect back to emergency page with error

                new_entry = {
                    "pname": cleaned_data['pname'],
                    "pmobile": pmobile,
                    "bg_needed": cleaned_data['bg_needed'],
                    "pgender": cleaned_data['pgender'],
                    "units_needed": cleaned_data['units_needed'],
                    "hospital_name": cleaned_data['hospital_name'],
                    "pdists": cleaned_data['pdists'],
                    "urgency_level": cleaned_data['urgency_level']
                }
                db[EMERGENCY_COLLECTION].insert_one(new_entry)
                logger.info(f"Emergency details saved for mobile: {pmobile}")
                messages.success(request, "Emergency details saved successfully!")
                return redirect('profile')  # Redirect to profile page with success
            except Exception as e:
                logger.error(f"Error saving emergency details: {str(e)}")
                messages.error(request, f"An error occurred while saving emergency details: {str(e)}")
                return redirect('emergency')  # Redirect back to emergency page with error
        else:
            messages.error(request, "Invalid form data!")
            return redirect('emergency')  # Redirect back to emergency page with error
    return render(request, 'Main/emergency.html', {'EmergencyForm': EmergencyForm()})

# Update report
@csrf_protect
@login_required
def updateReport(request):
    if request.method == 'POST':
        form = ReportForm(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            mobile = cleaned_data['rmobile']

            try:
                # Check for duplicate reports (optional, depending on requirements)
                existing_report = db[REPORTS_COLLECTION].find_one({"mobile": mobile, "report_type": cleaned_data['report_type']})
                if existing_report:
                    messages.error(request, "Report already exists for this mobile number and type!")
                    return redirect('report')  # Redirect back to report page with error

                # Validate mobile format (example: 10 digits)
                if not mobile.isdigit() or len(mobile) != 10:
                    messages.error(request, "Invalid mobile number format! Must be 10 digits.")
                    return redirect('report')  # Redirect back to report page with error

                new_entry = {
                    "mobile": mobile,
                    "report_type": cleaned_data['report_type'],
                    "description": cleaned_data['description'],
                }
                db[REPORTS_COLLECTION].insert_one(new_entry)
                logger.info(f"Report saved for mobile: {mobile}")
                messages.success(request, "Report saved successfully!")
                return redirect('profile')  # Redirect to profile page with success
            except Exception as e:
                logger.error(f"Error saving report: {str(e)}")
                messages.error(request, f"An error occurred while saving the report: {str(e)}")
                return redirect('report')  # Redirect back to report page with error
        else:
            messages.error(request, "Invalid form data!")
            return redirect('report')  # Redirect back to report page with error
    return render(request, 'Main/report.html', {'ReportForm': ReportForm()})

# Save user logs (signup)
@csrf_protect
def save_logs(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            username = cleaned_data['username']

            try:
                # Check for duplicate username
                existing_user = db[LOGS_COLLECTION].find_one({"username": username})
                if existing_user:
                    messages.error(request, "Username already exists!")
                    return redirect('signup')  # Redirect back to signup page with error

                # Validate username (e.g., no spaces, alphanumeric)
                if not username.replace('_', '').isalnum():
                    messages.error(request, "Username must be alphanumeric or contain underscores only!")
                    return redirect('signup')  # Redirect back to signup page with error

                user_id = generate_session_token()
                new_entry = {
                    "user_id": user_id,
                    "username": username,
                    "password": cleaned_data['password']  # Consider hashing the password in production
                }
                db[LOGS_COLLECTION].insert_one(new_entry)
                logger.info(f"New user registered: {username}")
                
                # Set cookie for the new user
                response = redirect('profile')  # Redirect to profile page after successful signup
                response.set_cookie("user_id", user_id, httponly=True, secure=True, samesite='Strict', max_age=2592000)  # 30 days, secure cookie
                messages.success(request, "User registered successfully!")
                return response
            except Exception as e:
                logger.error(f"Error saving user logs: {str(e)}")
                messages.error(request, f"An error occurred while registering: {str(e)}")
                return redirect('signup')  # Redirect back to signup page with error
        else:
            messages.error(request, "Invalid form data!")
            return redirect('signup')  # Redirect back to signup page with error
    return render(request, 'Main/profile-signup.html', {'form': SignupForm()})

# Login user
@csrf_protect
def login_user(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            username = cleaned_data['username']
            password = cleaned_data['password']

            try:
                user = db[LOGS_COLLECTION].find_one({"username": username, "password": password})
                if user:
                    session_token = user.get("user_id", generate_session_token())
                    response = redirect('profile')  # Redirect to profile page after successful login
                    response.set_cookie("user_id", session_token, httponly=True, secure=True, samesite='Strict', max_age=2592000)  # 30 days, secure cookie
                    logger.info(f"User logged in: {username}")
                    messages.success(request, "Login successful!")
                    return response
                else:
                    messages.error(request, "Invalid username or password!")
                    return redirect('login')  # Redirect back to login page with error
            except Exception as e:
                logger.error(f"Error during login: {str(e)}")
                messages.error(request, f"Login failed: {str(e)}")
                return redirect('login')  # Redirect back to login page with error
        else:
            messages.error(request, "Invalid form data!")
            return redirect('login')  # Redirect back to login page with error
    return render(request, 'Main/profile-login.html', {'form': LoginForm()})
# In views.py, add this view at the end or within the existing views:

@login_required  # Optional: Restrict access to logged-in users
def download_app(request):
    return render(request, 'Main/download.html')

def download_apk(request):
    apk_path = os.path.join(settings.STATICFILES_DIRS[0], 'apps', 'BCview.apk')
    response = FileResponse(open(apk_path, 'rb'), as_attachment=True, filename='BCview.apk')
    response['Content-Type'] = 'application/vnd.android.package-archive'
    response['Content-Disposition'] = 'attachment; filename="BCview.apk"'
    return response

# Logout view
def logout(request):
    response = HttpResponse("Logged out successfully.")
    response.delete_cookie('user_id')  # Delete the 'user_id' cookie
    messages.success(request, "You have been logged out successfully.")
    logger.info("User logged out")
    return redirect('login')
