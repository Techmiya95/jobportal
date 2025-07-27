def user_list(request):
    users = list(auth_user_collection.find({}))  # Fetch users
    print(f"Fetched Users: {users}")  # Debugging line to check fetched users
    user_id = "19"  # Check for user with ID 19
    user_data = auth_user_collection.find_one({"_id": user_id})
    print(f"User Data for ID {user_id}: {user_data}")  # Debugging line to check specific user data
    social_auths = list(social_auth_collection.find({}))  # Fetch social auth users
    
    return render(request, 'user_list.html', {'users': users, 'social_auths': social_auths})
from django.shortcuts import render
from pymongo import MongoClient
from django.shortcuts import render, redirect

from django.http import HttpResponse
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import datetime


# Other views (e.g., job_list_view, signup, login_view, etc.) remain unchanged
# Connect to MongoDB Atlas (First Database)
MONGO_URI = "mongodb+srv://jobportal:techmiya@jobportal.qhq2faj.mongodb.net/"
client = MongoClient(MONGO_URI)
db = client["test_mongo2"]

# Connect to MongoDB Atlas (Second Database)
MONGO_URI1 = "mongodb+srv://jobportal:techmiya@jobportal.qhq2faj.mongodb.net/"
client1 = MongoClient(MONGO_URI1)
db1 = client1["test_mongo1"]

# Collections
Experience = db1["Experience"]
hr_collection = db1["authhr"]
auth_user_collection = db["auth_user"]
social_auth_collection = db["social_auth_usersocialauth"]
job_collection = db1["Joblist"]  # Renamed to avoid conflict
job_applied_collection = db1["JobApplied"]  # Renamed to avoid conflict
skills_collection = db["skills"]  # Renamed to avoid conflict
location_collection=db["location"]
jobrole_collection=db["jobrole"]
education_collection=db["educations"]

from bson import ObjectId
from datetime import datetime
import json
from django.http import JsonResponse

class MongoJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

def user_list(request):
    users = list(auth_user_collection.find({}))
    social_auths = list(social_auth_collection.find({}))
    
    # Convert to JSON using our custom encoder
    users_json = json.loads(json.dumps(users, cls=MongoJSONEncoder))
    social_auths_json = json.loads(json.dumps(social_auths, cls=MongoJSONEncoder))
    
    response = JsonResponse({
        'users': users_json,
        'social_auths': social_auths_json
    })
    response["Access-Control-Allow-Origin"] = "*"
    return response


def api_jobs(request):
    return render(request, 'Api_job.html')

from datetime import datetime
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def job_list_view(request):
    # Handle AJAX requests for job role and location suggestions
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' and 'term' in request.GET:
        search_term = request.GET.get('term', '').lower()
        field = request.GET.get('field', '')
        
        if field == 'job_role':
            roles_doc = jobrole_collection.find_one({}, {"job_roles": 1})
            job_roles = roles_doc.get('job_roles', []) if roles_doc else []
            suggestions = [role for role in job_roles if role and search_term in role.lower()][:10]
            return JsonResponse(suggestions, safe=False)
        elif field == 'location':
            locs_doc = location_collection.find_one({}, {"locations": 1})
            locations = locs_doc.get('locations', []) if locs_doc else []
            suggestions = [loc for loc in locations if loc and search_term in loc.lower()][:10]
            return JsonResponse(suggestions, safe=False)

    # Get current date in the same format as deadline (YYYY-MM-DD)
    current_date = datetime.now().strftime("%Y-%m-%d")

    # Fetch only active jobs where deadline is greater than or equal to current date
    jobs = list(job_collection.find({
        "deadline": {"$gte": current_date},
        "$or": [
            {"disabled": {"$exists": False}},
            {"disabled": False}
        ]
    }).sort("posted_date", -1))
    
    # Process each job to clean up data formats
    for job in jobs:
        job['jid'] = str(job['_id'])  # Convert ObjectId to string
        
        # Fix Location format (handle both string and array formats)
        if 'Location' in job:
            if isinstance(job['Location'], str):
                # Handle string format like "["Lakshadweep"]"
                loc_value = job['Location'].strip()
                if loc_value.startswith('[') and loc_value.endswith(']'):
                    try:
                        job['Location'] = [loc.strip(' "\'') for loc in loc_value[1:-1].split(',')]
                    except:
                        job['Location'] = [job['Location']]
                else:
                    job['Location'] = [job['Location']]
            elif not isinstance(job['Location'], list):
                job['Location'] = [str(job['Location'])]
            
            # Add a new field for display purposes
            job['location_display'] = ', '.join(job['Location'])
        
        # Convert skills to list if stored as string
        if 'Skills' in job and isinstance(job['Skills'], str):
            job['Skills'] = [skill.strip() for skill in job['Skills'].split(',')]
            job['skills_display'] = ', '.join(job['Skills'])
        
        # Similarly fix education format if needed
        if 'education' in job:
            if isinstance(job['education'], str):
                edu_value = job['education'].strip()
                if edu_value.startswith('[') and edu_value.endswith(']'):
                    try:
                        job['education'] = [edu.strip(' "\'') for edu in edu_value[1:-1].split(',')]
                    except:
                        job['education'] = [job['education']]
                else:
                    job['education'] = [job['education']]
            elif not isinstance(job['education'], list):
                job['education'] = [str(job['education'])]
            job['education_display'] = ', '.join(job['education'])

    # Get user data if authenticated
    user_data = None
    user_mongo_id = None
    if request.user.is_authenticated:
        user_data = auth_user_collection.find_one({"id": request.user.id})
        if user_data:
            user_mongo_id = str(user_data['_id'])

    # Get applied jobs for the current user
    applied_jobs = set()
    if user_mongo_id:
        applications = job_applied_collection.find({
            "user_id": user_mongo_id,
            "$or": [
                {"disabled": {"$exists": False}},
                {"disabled": False}
            ]
        })
        applied_jobs = {str(app['job_id']) for app in applications}

    # Get all available job roles and locations for filters
    roles_doc = jobrole_collection.find_one({}, {"job_roles": 1})
    job_roles = roles_doc.get('job_roles', []) if roles_doc else []
    
    locs_doc = location_collection.find_one({}, {"locations": 1})
    locations = locs_doc.get('locations', []) if locs_doc else []
    
    # Clean locations data
    locations = [str(loc).strip() for loc in locations if loc is not None]

    return render(request, 'job_list.html', {
        'jobs': jobs,
        'applied_jobs': applied_jobs,
        'user': request.user,
        'job_roles': sorted(job_roles, key=lambda x: x.lower()),
        'locations': sorted(locations, key=lambda x: x.lower()),
    })
def job_detail_view(request, job_id):
    # Get the job details
    try:
        from bson.objectid import ObjectId
        job = job_collection.find_one({"_id": ObjectId(job_id)})
        if not job:
            raise Http404("Job not found")
        
        job['jid'] = str(job['_id'])  # Convert ObjectId to string
        
        # Convert skills to list if they're stored as strings
        if 'Skills' in job and isinstance(job['Skills'], str):
            job['Skills'] = [skill.strip() for skill in job['Skills'].split(',')]
    except:
        raise Http404("Invalid job ID")

    # Check if user has applied for this job
    applied = False
    if request.user.is_authenticated:
        user_data = auth_user_collection.find_one({"id": request.user.id})
        if user_data:
            user_mongo_id = str(user_data['_id'])
            application = job_applied_collection.find_one({
                "user_id": user_mongo_id,
                "job_id": job_id,
            })
            applied = application is not None

    return render(request, 'job_detail.html', {
        'job': job,
        'applied': applied,
        'hr_id': job.get('hr_id', '')  # Pass HR ID to template
    })




def hr_list(request):
 return render(request, 'hr.html')

def index(request):
    return render(request, 'authunticate.html')

def add_person(request):
    person = Person(name="Doe", age=30)
    person.save()
    return HttpResponse("<h1>Person added successfully</h1>")

def get_person(request):
    person = Person.objects.first() # Get first person
    return HttpResponse(f"<h1>Name: {person.name}, Age: {person.age}</h1>")

def check_auth(request):
    if request.user.is_authunticated:
        return HttpResponse(f"<h1>User is authenticated</h1>")
    return HttpResponse(f"<h1>User is not authenticated</h1>")

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

def signup(request):
    if request.method == "POST":
        email = request.POST.get('email', '').strip()
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()
        phone_number = request.POST.get('phone_number', '').strip()
        print(phone_number)

        # Validation checks
        errors = []
        
        if not all([email, username, password, confirm_password, phone_number]):
            errors.append("All fields are required")
        
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        try:
            validate_email(email)
        except ValidationError:
            errors.append("Invalid email format")
        
        if User.objects.filter(email=email).exists():
            errors.append("Email already exists")
        
        if User.objects.filter(username=username).exists():
            errors.append("Username already exists")
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters")
        
        if errors:
            return render(request, "authunticate.html", {
                "error_message": ", ".join(errors),
                "form_data": {
                    'email': email,
                    'username': username,
                    'phone_number': phone_number
                }
            })

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            # Assuming you have a phone_number field in your User model
            
        # Assuming you have a phone_number field in your User model
        )
        # Add phone number to user profile if you have a profile model
        # user.profile.phone_number = phone_number
        # user.profile.save()
        
        messages.success(request, "Registration successful! Please login.")
        return redirect('login')

    return redirect('/')

def login_view(request):
    if request.method == 'POST':
        username_or_email = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        next_url = request.POST.get('next', '') or request.GET.get('next', 'job_list')

        if not username_or_email or not password:
            messages.error(request, "Please fill in all fields")
            return render(request, "authunticate.html", {
                'error_message': "Please fill in all fields",
                'username_or_email': username_or_email,
                'next': next_url
            })

        # Determine if login is via email or username
        if '@' in username_or_email:
            kwargs = {'email': username_or_email}
        else:
            kwargs = {'username': username_or_email}

        try:
            user = User.objects.get(**kwargs)
        except User.DoesNotExist:
            messages.error(request, "Invalid credentials")
            return render(request, "authunticate.html", {
                'error_message': "Invalid credentials",
                'username_or_email': username_or_email,
                'next': next_url
            })

        # Authenticate with username (since authenticate doesn't work with email directly)
        user = authenticate(request, username=user.username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect(next_url)
        else:
            messages.error(request, "Invalid password")
            return render(request, "authunticate.html", {
                'error_message': "Invalid password",
                'username_or_email': username_or_email,
                'next': next_url
            })

    # If GET request, show login page
    return render(request, "authunticate.html", {
        'next': request.GET.get('next', 'job_list')
    })

def loginhr(request):
    return render(request, 'authhr.html')



# hr authentication
def hr_signup(request):
    if request.method == "POST":
        # Get all form data
        first_name = request.POST.get('firstname', '').strip()
        last_name = request.POST.get('lastname', '').strip()
        mobile = request.POST.get('mobile', '').strip()
        email = request.POST.get('email', '').strip()
        hrname = request.POST.get('hrname', '').strip()
        password = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        # Validate required fields
        if not all([first_name, last_name, mobile, email, hrname, password, confirm_password]):
            return render(request, "authhr.html", {"error_message": "All fields are required"})

        # Validate mobile number format
        if not mobile.isdigit() or len(mobile) != 10:
            return render(request, "authhr.html", {"error_message": "Mobile number must be 10 digits"})

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return render(request, "authhr.html", {"error_message": "Please enter a valid email address"})

        # Validate password match
        if password != confirm_password:
            return render(request, "authhr.html", {"error_message": "Passwords do not match"})

        # Validate password complexity
        if (len(password) < 8 or len(password) > 12 or 
            not any(char.isupper() for char in password) or 
            not any(char.isdigit() for char in password) or 
            not any(char in '!@#$%^&*' for char in password)):
            return render(request, "authhr.html", {"error_message": "Password must be 8-12 characters with at least 1 uppercase letter, 1 digit, and 1 special character"})

        # Check if HR already exists
        if hr_collection.find_one({"$or": [{"email": email}, {"hrname": hrname}]}):
            return render(request, "authhr.html", {"error_message": "HR with this email or username already exists"})

        # Create HR record
        hashed_password = make_password(password)
        hr_data = {
            "hrname": hrname,
            "email": email,
            "password": hashed_password,
            "mobile": mobile,
            "first_name": first_name,
            "last_name": last_name,
            "is_active": True,
            "is_staff": False,
            "is_superuser": False,
        }
        
        try:
            hr_collection.insert_one(hr_data)
            return redirect('hrlogin')
        except Exception as e:
            return render(request, "authhr.html", {"error_message": f"An error occurred: {str(e)}"})

    return redirect('/')




def hr_login(request):
    if request.method == "POST":
        identifier = request.POST.get("identifier", "").strip()  # Accepts hrname or email
        password = request.POST.get("password", "").strip()

        print("Received data:", request.POST)  # Debugging

        if not identifier or not password:
            return render(request, "authhr.html", {"error_message": "Both fields are required"})

        hr = hr_collection.find_one({"$or": [{"hrname": identifier}, {"email": identifier}]})

        if hr:
            print("Found HR:", hr)  # Debugging

            if check_password(password, hr["password"]):
                # Store HR information in the session
                request.session["hr_username"] = hr["hrname"]
                request.session["hr_id"] = str(hr["_id"])

                # Redirect to HR dashboard without using Django's auth system
                return redirect("hr_panel")
            else:
                print("Password mismatch")  # Debugging
        else:
            print("HR not found")  # Debugging

        return redirect('loginhr')

    return redirect('loginhr')  # Show login page if GET request

def hr_logout(request):
    # Remove HR-specific session data
    if 'hr_username' in request.session:
        del request.session['hr_username']
    if 'hr_id' in request.session:
        del request.session['hr_id']
    
    # Alternatively, you could clear the entire session
    # request.session.flush()
    
    # Redirect to HR login page
    return redirect('loginhr')

@login_required(login_url='/')
def dashbord(request):
    print("hiii")
    # return render(request, 'job_list.html',{"user": request.user})

from django.shortcuts import redirect

def logout_view(request):
    if request.user.is_authenticated:  # Optional check
        request.session.flush()  # Clears all session data
    return redirect('login')  # Redirects to login page

def payment(request):
    return render(request, 'payment.html')

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from datetime import datetime


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from datetime import datetime

@csrf_exempt
@login_required
def toggle_apply_job(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request"}, status=400)
    
    try:
        job_id = request.POST.get("job_id", "").strip()
        hr_id = request.POST.get("hr_id", "").strip()
        
        # Get user's MongoDB _id
        user = auth_user_collection.find_one({"id": request.user.id})
        if not user:
            return JsonResponse({"error": "User not found"}, status=400)
        user_id = str(user["_id"])
        
        # Validate IDs
        if not job_id or not hr_id:
            return JsonResponse({"error": "Missing IDs"}, status=400)
        
        # Check existing application
        existing = job_applied_collection.find_one({
            "user_id": user_id,
            "job_id": job_id
        })
        
        if existing:
            # Unapply
            job_applied_collection.delete_one({"_id": existing["_id"]})
            return JsonResponse({"status": "unapplied"})
        else:
            # Apply
            job_applied_collection.insert_one({
                "user_id": user_id,
                "job_id": job_id,
                "hr_id": hr_id,
                "applied_at": datetime.now()
            })
            return JsonResponse({"status": "applied"})
            
    except Exception as e:
        print(f"Error in toggle_apply_job: {str(e)}")
        return JsonResponse({"error": "Server error"}, status=500)
# profile side bar logic
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

def get_user_profile(request):
    user = request.user
    user_data = auth_user_collection .find_one({"id": request.user.id})
    user_name = user_data.get("username", "N/A")
    ug_college = user_data.get("ug_college", "N/A")
    email = user_data.get("email", "N/A")
    father_name = user_data.get("father_name", "N/A")
    progress = user_data.get("progress", "N/A")
    branch = user_data.get("branch", "N/A")
    Passout_Year = user_data.get("Passout_Year", "N/A")
    Graduation_Percentage = user_data.get("Graduation_Percentage", "N/A")
    Percentage_10 = user_data.get("10th_Percentage", "N/A")
    profile_picture = user_data.get("profile_picture", None)
    mobile = user_data.get("mobile", "N/A")
    location = user_data.get("location", "N/A")
    tenth_school = user_data.get("10th_school", "N/A")
    tenth_board = user_data.get("10th_board", "N/A")
    tenth_passout_year = user_data.get("10th_passout_year", "N/A")
    twelfth_school = user_data.get("12th_school", "N/A")
    twelfth_board = user_data.get("12th_board", "N/A")
    twelfth_passout_year = user_data.get("12th_passout_year", "N/A")
    twelfth_percentage = user_data.get("12th_Percentage", "N/A")
    skills = user_data.get("skills", [])  # Fetch skills from user document
  
    data = [{
    # "father_name": father_name,
    "profile_picture": profile_picture,
    "email": email,
    "father_name": father_name,
    "progress": progress,
    "branch": branch,
    "ug_college": ug_college,
    "user_name": user_name,
    "Passout_Year": Passout_Year,
    "Graduation_Percentage": Graduation_Percentage,
    "Percentage_10": Percentage_10,
    "mobile": mobile,
    "location": location,
    "tenth_school": tenth_school,
    "tenth_board": tenth_board,
    "tenth_year": tenth_passout_year,
    "twelfth_school": twelfth_school,
    "twelfth_board": twelfth_board,
    "twelfth_year": twelfth_passout_year,
    "twelfth_percentage": twelfth_percentage,
    "skills": skills,  # Include skills in the response 
       
    }]
    return JsonResponse({"success": True, "data": data})


@csrf_exempt
def generate_resume(request, template_id):
    if request.method == 'GET':
        # Just return the user data - the PDF generation will happen in JavaScript
        user_data = get_user_profile(request)
        return user_data
    return JsonResponse({"success": False, "error": "Invalid request method"})

# Similar functions for template2, template3, template4 would be implemented
import json
import base64
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from pymongo import MongoClient


# @csrf_exempt
# @require_POST
# def update_profile(request):
#     try:
#         user = request.user  
#         if not user.is_authenticated:  
#             return JsonResponse({"status": "error", "message": "User not authenticated"}, status=401)

#         # Check if request is multipart/form-data (for file upload)
#         if request.content_type.startswith('multipart/form-data'):
#             data = request.POST.dict()  # Convert form data to dict
#             profile_picture = request.FILES.get("profile_picture")  # Get uploaded file
#         else:
#             try:
#                 data = json.loads(request.body.decode("utf-8"))
#                 profile_picture = None
#             except json.JSONDecodeError:
#                 return JsonResponse({"status": "error", "message": "Invalid JSON data"}, status=400)

#         print(f"Received data: {data}")  # Debugging

#         # Fetch user data from MongoDB
#         user_data = auth_user_collection.find_one({"username": user.username})

#         if not user_data:
#             return JsonResponse({"status": "error", "message": "User profile not found"}, status=404)

#         # Field mappings
#         field_mappings = {
#             "name": "username",
#             "email": "email",
#             "father_name": "father_name",
#             "ug_college": "ug_college",
#             "branch": "branch",
#             "passout_year": "Passout_Year",
#             "graduation_percentage": "Graduation_Percentage",
#             "tenth_percentage": "10th_Percentage",
#             "twelfth_percentage": "12th_Percentage",
#         }

#         update_data = {}
#         for frontend_field, db_field in field_mappings.items():
#             new_value = data.get(frontend_field, "").strip()
#             old_value = str(user_data.get(db_field, "")).strip()

#             if new_value and new_value != old_value:
#                 update_data[db_field] = new_value

#         # **Handle profile picture upload**
#         if profile_picture:
#             image_data = profile_picture.read()  # Read the image file
#             encoded_image = base64.b64encode(image_data).decode("utf-8")  # Convert to Base64
#             update_data["profile_picture"] = encoded_image  # Store in MongoDB

#         # print(f"Changes detected: {update_data}")  # Debugging

#         if not update_data:
#             return JsonResponse({"status": "success", "message": "No changes detected."})

#         # Update user profile in MongoDB
#         result = auth_user_collection.update_one(
#             {"username": user.username},
#             {"$set": update_data}
#         )

#         print(f"Update result: {result.modified_count} document(s) modified.")  # Debugging

#         return JsonResponse({"status": "success", "message": "Profile updated successfully!"})

#     except Exception as e:
#         print(f"Error updating profile: {e}")  # Debugging
#         return JsonResponse({"status": "error", "message": str(e)}, status=500)
    
#     from django.shortcuts import render
# from django.contrib.auth.decorators import login_required

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from bson import ObjectId
from datetime import datetime

@csrf_exempt
def get_experiences(request):
    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"success": False, "error": "User not authenticated"}, status=401)

        user_data = auth_user_collection.find_one({"username": user.username})
        if not user_data:
            return JsonResponse({"success": False, "error": "User not found"}, status=404)

        experiences = user_data.get("experiences", [])
        
        # Convert ObjectId to string for JSON serialization
        for exp in experiences:
            if '_id' in exp:
                exp['_id'] = str(exp['_id'])
                
        return JsonResponse({"success": True, "data": experiences})
        
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@csrf_exempt
def add_experience(request):
    if request.method != 'POST':
        return JsonResponse({"success": False, "error": "Method not allowed"}, status=405)

    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"success": False, "error": "User not authenticated"}, status=401)

        data = json.loads(request.body)
        
        # Validate required fields
        required_fields = ['company_name', 'job_title', 'start_date']
        for field in required_fields:
            if field not in data or not data[field]:
                return JsonResponse({"success": False, "error": f"Missing required field: {field}"}, status=400)

        experience_data = {
            "_id": ObjectId(),  # Generate new ObjectId
            "company_name": data['company_name'],
            "job_title": data['job_title'],
            "start_date": data['start_date'],
            "end_date": data.get('end_date'),
            "currently_working": data.get('currently_working', False),
            "description": data.get('description', '')
        }

        # Update MongoDB
        result = auth_user_collection.update_one(
            {"username": user.username},
            {"$push": {"experiences": experience_data}}
        )

        if result.modified_count == 1:
            return JsonResponse({"success": True, "experience_id": str(experience_data['_id'])})
        else:
            return JsonResponse({"success": False, "error": "Failed to add experience"}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON data"}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@csrf_exempt
def update_experience(request):
    if request.method != 'PUT':
        return JsonResponse({"success": False, "error": "Method not allowed"}, status=405)

    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"success": False, "error": "User not authenticated"}, status=401)

        data = json.loads(request.body)
        
        if not data.get('experience_id'):
            return JsonResponse({"success": False, "error": "Missing experience_id"}, status=400)

        # Validate required fields
        required_fields = ['company_name', 'job_title', 'start_date']
        for field in required_fields:
            if field not in data or not data[field]:
                return JsonResponse({"success": False, "error": f"Missing required field: {field}"}, status=400)

        update_data = {
            "experiences.$.company_name": data['company_name'],
            "experiences.$.job_title": data['job_title'],
            "experiences.$.start_date": data['start_date'],
            "experiences.$.end_date": data.get('end_date'),
            "experiences.$.currently_working": data.get('currently_working', False),
            "experiences.$.description": data.get('description', '')
        }

        # Update MongoDB
        result = auth_user_collection.update_one(
            {"username": user.username, "experiences._id": ObjectId(data['experience_id'])},
            {"$set": update_data}
        )

        if result.modified_count == 1:
            return JsonResponse({"success": True})
        else:
            return JsonResponse({"success": False, "error": "Experience not found or not modified"}, status=404)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON data"}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@csrf_exempt
def delete_experience(request):
    if request.method != 'DELETE':
        return JsonResponse({"success": False, "error": "Method not allowed"}, status=405)

    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"success": False, "error": "User not authenticated"}, status=401)

        data = json.loads(request.body)
        
        if not data.get('experience_id'):
            return JsonResponse({"success": False, "error": "Missing experience_id"}, status=400)

        # Update MongoDB
        result = auth_user_collection.update_one(
            {"username": user.username},
            {"$pull": {"experiences": {"_id": ObjectId(data['experience_id'])}}}
        )

        if result.modified_count == 1:
            return JsonResponse({"success": True})
        else:
            return JsonResponse({"success": False, "error": "Experience not found or not deleted"}, status=404)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON data"}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)
    
    from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from bson import ObjectId
from datetime import datetime

@csrf_exempt
def get_projects(request):
    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"success": False, "error": "User not authenticated"}, status=401)

        user_data = auth_user_collection.find_one({"username": user.username})
        if not user_data:
            return JsonResponse({"success": False, "error": "User not found"}, status=404)

        projects = user_data.get("projects", [])
        
        # Convert ObjectId to string for JSON serialization
        for proj in projects:
            if '_id' in proj:
                proj['_id'] = str(proj['_id'])
                
        return JsonResponse({"success": True, "data": projects})
        
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@csrf_exempt
def add_project(request):
    if request.method != 'POST':
        return JsonResponse({"success": False, "error": "Method not allowed"}, status=405)

    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"success": False, "error": "User not authenticated"}, status=401)

        data = json.loads(request.body)
        
        # Validate required fields
        required_fields = ['title', 'start_date']
        for field in required_fields:
            if field not in data or not data[field]:
                return JsonResponse({"success": False, "error": f"Missing required field: {field}"}, status=400)

        project_data = {
            "_id": ObjectId(),  # Generate new ObjectId
            "title": data['title'],
            "start_date": data['start_date'],
            "end_date": data.get('end_date'),
            "currently_ongoing": data.get('currently_ongoing', False),
            "description": data.get('description', ''),
            "link": data.get('link', '')
        }

        # Update MongoDB
        result = auth_user_collection.update_one(
            {"username": user.username},
            {"$push": {"projects": project_data}}
        )

        if result.modified_count == 1:
            return JsonResponse({"success": True, "project_id": str(project_data['_id'])})
        else:
            return JsonResponse({"success": False, "error": "Failed to add project"}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON data"}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@csrf_exempt
def update_project(request):
    if request.method != 'PUT':
        return JsonResponse({"success": False, "error": "Method not allowed"}, status=405)

    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"success": False, "error": "User not authenticated"}, status=401)

        data = json.loads(request.body)
        
        if not data.get('project_id'):
            return JsonResponse({"success": False, "error": "Missing project_id"}, status=400)

        # Validate required fields
        required_fields = ['title', 'start_date']
        for field in required_fields:
            if field not in data or not data[field]:
                return JsonResponse({"success": False, "error": f"Missing required field: {field}"}, status=400)

        update_data = {
            "projects.$.title": data['title'],
            "projects.$.start_date": data['start_date'],
            "projects.$.end_date": data.get('end_date'),
            "projects.$.currently_ongoing": data.get('currently_ongoing', False),
            "projects.$.description": data.get('description', ''),
            "projects.$.link": data.get('link', '')
        }

        # Update MongoDB
        result = auth_user_collection.update_one(
            {"username": user.username, "projects._id": ObjectId(data['project_id'])},
            {"$set": update_data}
        )

        if result.modified_count == 1:
            return JsonResponse({"success": True})
        else:
            return JsonResponse({"success": False, "error": "Project not found or not modified"}, status=404)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON data"}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@csrf_exempt
def delete_project(request):
    if request.method != 'DELETE':
        return JsonResponse({"success": False, "error": "Method not allowed"}, status=405)

    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"success": False, "error": "User not authenticated"}, status=401)

        data = json.loads(request.body)
        
        if not data.get('project_id'):
            return JsonResponse({"success": False, "error": "Missing project_id"}, status=400)

        # Update MongoDB
        result = auth_user_collection.update_one(
            {"username": user.username},
            {"$pull": {"projects": {"_id": ObjectId(data['project_id'])}}}
        )

        if result.modified_count == 1:
            return JsonResponse({"success": True})
        else:
            return JsonResponse({"success": False, "error": "Project not found or not deleted"}, status=404)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON data"}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)
@csrf_exempt
@require_POST
def update_profile(request):
    try:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({"status": "error", "message": "User not authenticated"}, status=401)

        # Check if request is multipart/form-data (for file upload)
        if request.content_type.startswith('multipart/form-data'):
            data = request.POST.dict()  # Convert form data to dict
            profile_picture = request.FILES.get("profile_picture")  # Get uploaded file
        else:
            try:
                data = json.loads(request.body.decode("utf-8"))
                profile_picture = None
            except json.JSONDecodeError:
                return JsonResponse({"status": "error", "message": "Invalid JSON data"}, status=400)

        # print(f"Received data: {data}")  # Debugging

        # Fetch user data from MongoDB
        user_data = auth_user_collection.find_one({"username": user.username})

        if not user_data:
            return JsonResponse({"status": "error", "message": "User profile not found"}, status=404)

        # Field mappings for personal information
        field_mappings = {
            "username": "username",  # Match the name attribute in the form
            "email": "email",  # Match the name attribute in the form
            "father_name": "father_name",  # Match the name attribute in the form
            "mobile": "mobile",  # Match the name attribute in the form
            "location": "location",  # Match the name attribute in the form
            "tenth_school": "10th_school",  # Match the name attribute in the form
            "tenth_board": "10th_board",  # Match the name attribute in the form  
            "tenth_year": "10th_passout_year",  # Match the name attribute in the form
            "tenth_percentage": "10th_Percentage",  # Match the name attribute in the form
            "twelfth_school": "12th_school",  # Match the name attribute in the form
            "twelfth_board": "12th_board",  # Match the name attribute in the form
            "twelfth_year": "12th_passout_year",  # Match the name attribute in
            "twelfth_percentage": "12th_Percentage",  # Match the name attribute in the form
            "ug_college": "ug_college",  # Match the name attribute in the form
            "branch": "branch",  # Match the name attribute in the form
            "passout_year": "Passout_Year",  # Match the name attribute in the form
            "graduation_percentage": "Graduation_Percentage",  # Match the name attribute in the form
            
            
            
        }

        update_data = {}
        for frontend_field, db_field in field_mappings.items():
            new_value = data.get(frontend_field, "").strip()
            old_value = str(user_data.get(db_field, "")).strip()

            if new_value and new_value != old_value:
                update_data[db_field] = new_value

        # Handle profile picture upload
        if profile_picture:
            image_data = profile_picture.read()  # Read the image file
            encoded_image = base64.b64encode(image_data).decode("utf-8")  # Convert to Base64
            update_data["profile_picture"] = encoded_image  # Store in MongoDB

        # print(f"Changes detected: {update_data}")  # Debugging

        if not update_data:
            return JsonResponse({"status": "success", "message": "No changes detected."})

        # Update user profile in MongoDB
        result = auth_user_collection.update_one(
            {"username": user.username},
            {"$set": update_data}
        )

        # print(f"Update result: {result.modified_count} document(s) modified.")  # Debugging

        return JsonResponse({"status": "success", "message": "Profile updated successfully!"})

    except Exception as e:
        print(f"Error updating profile: {e}")  # Debugging
        return JsonResponse({"status": "error", "message": str(e)}, status=500)
@login_required
def profile_page(request):
    """
    View to render the profile page HTML
    """
    return render(request, 'profile.html')
def base_page(request):
    """
    View to render the base page HTML
    """
    return render(request, 'base.html')


import os
import json
from datetime import datetime as dt  # Changed import to avoid conflict
from django.http import JsonResponse, FileResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

# Path to store resumes
RESUME_DIR = os.path.join(settings.MEDIA_ROOT, 'resumes')
RESUME_INFO_FILE = os.path.join(RESUME_DIR, 'resume_info.json')

def ensure_resume_dir():
    """Ensure the resume directory exists"""
    if not os.path.exists(RESUME_DIR):
        os.makedirs(RESUME_DIR)

def get_user_resume_filename(user_id):
    """Get the filename for a user's resume"""
    return f"resume_{user_id}.pdf"

def save_resume_info(user_id, filename, file_size):
    """Save resume metadata to a JSON file"""
    ensure_resume_dir()
    info = {}
    
    if os.path.exists(RESUME_INFO_FILE):
        with open(RESUME_INFO_FILE, 'r') as f:
            try:
                info = json.load(f)
            except json.JSONDecodeError:
                info = {}
    
    info[str(user_id)] = {
        'filename': filename,
        'file_size': file_size,
        'updated_at': dt.now().isoformat()  # Using dt instead of datetime
    }
    
    with open(RESUME_INFO_FILE, 'w') as f:
        json.dump(info, f, indent=4)

def get_resume_info(user_id):
    """Get resume metadata from JSON file"""
    if not os.path.exists(RESUME_INFO_FILE):
        return None
    
    with open(RESUME_INFO_FILE, 'r') as f:
        try:
            info = json.load(f)
            return info.get(str(user_id))
        except json.JSONDecodeError:
            return None

def delete_resume_file(user_id):
    """Delete a user's resume file"""
    filename = get_user_resume_filename(user_id)
    filepath = os.path.join(RESUME_DIR, filename)
    if os.path.exists(filepath):
        os.remove(filepath)

@csrf_exempt
def upload_resume(request):
    if request.method == 'POST' and request.FILES.get('resume'):
        if not request.user.is_authenticated:
            return JsonResponse({'success': False, 'message': 'Not authenticated'}, status=401)
        
        resume_file = request.FILES['resume']
        user_id = request.user.id
        
        # Delete old resume if exists
        delete_resume_file(user_id)
        
        # Save new resume
        ensure_resume_dir()
        filename = get_user_resume_filename(user_id)
        filepath = os.path.join(RESUME_DIR, filename)
        
        with open(filepath, 'wb+') as destination:
            for chunk in resume_file.chunks():
                destination.write(chunk)
        
        # Save metadata
        save_resume_info(user_id, resume_file.name, resume_file.size)
        
        return JsonResponse({
            'success': True,
            'resume': {
                'filename': resume_file.name,
                'updated_at': dt.now().isoformat()  # Using dt instead of datetime
            }
        })
    
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

def get_resume(request):
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'message': 'Not authenticated'}, status=401)
    
    resume_info = get_resume_info(request.user.id)
    if resume_info:
        return JsonResponse({
            'success': True,
            'resume': {
                'filename': resume_info['filename'],
                'updated_at': resume_info['updated_at']
            }
        })
    return JsonResponse({'success': True, 'resume': None})

def download_resume(request):
    
    if not request.user.is_authenticated:
        return HttpResponse('Not authenticated', status=401)
    
    resume_info = get_resume_info(request.user.id)
    if not resume_info:
        return HttpResponse('Resume not found', status=404)
    
    filename = get_user_resume_filename(request.user.id)
    print(f"Downloading resume: {filename}")  # Debugging
    filepath = os.path.join(RESUME_DIR, filename)
    
    if os.path.exists(filepath):
        response = FileResponse(open(filepath, 'rb'))
        username = request.user.username
        response['Content-Disposition'] = f'attachment; filename="{username}.pdf"'
        return response
    return HttpResponse('File not found', status=404)

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def add_skill(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        skill = data.get('skill')
        user = request.user
        auth_user_collection.update_one(
            {"id": user.id},
            {"$push": {"skills": skill}}
        )
        return JsonResponse({"success": True, "skill": skill})
    return JsonResponse({"success": False, "error": "Invalid request method"})


@csrf_exempt
def remove_skill(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        skill = data.get('skill')
        user = request.user
        auth_user_collection.update_one(
            {"id": user.id},
            {"$pull": {"skills": skill}}
        )
        return JsonResponse({"success": True, "skill": skill})
    return JsonResponse({"success": False, "error": "Invalid request method"})


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

from django.http import JsonResponse
from bson import ObjectId
# def get_projects(request):
#     user_id = request.GET.get('user_id')
#     print(f"Fetching projects for user_id: {user_id}")  # Debugging
#     projects = list(Experience.find({"user_id": user_id}))
#     print(f"Projects found: {projects}")  # Debugging
#     for project in projects:
#         project['_id'] = str(project['_id'])
#     return JsonResponse({"success": True, "data": projects})


    
    # views.py

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from bson.objectid import ObjectId
import json
from datetime import datetime

# Create your HR dashboard view




# @login_required
# def hr_dashboard(request):
#     if not request.session.get('hr_id'):
#         messages.error(request, "You need to log in as an HR to access this page.")
#         return redirect('hr_login')
    
#     hr_id = request.session.get('hr_id')
#     print(f"HR ID: {hr_id}")
    
#     # Fetch jobs created by the current HR
#     hr_jobs = list(job_collection.find({"hr_id": hr_id}))
#     print(hr_jobs)
    
#     # Convert ObjectId to string for each job
#     for job in hr_jobs:
#         job['_id'] = str(job['_id'])
        
#         # Convert Skills to list if it's a string
#         if 'Skills' in job and isinstance(job['Skills'], str):
#             job['Skills'] = [skill.strip() for skill in job['Skills'].split(',')]
        
#         # Count applicants for each job
#         job['applicants_count'] = job_applied_collection.count_documents({"job_id": str(job['_id'])})
    
#     # Fetch job applications for jobs created by this HR
#     job_ids = [job['_id'] for job in hr_jobs]
#     applications = list(job_applied_collection.find({"job_id": {"$in": job_ids}}))
    
#     job_applications = []
#     for app in applications:
#         # Get job details
#         job = job_collection.find_one({"_id": ObjectId(app['job_id'])})
        
#         if job:
#             # Get user details
#             user_details = auth_user_collection.find_one({"id": int(app['user_id'])})
#             user = User.objects.get(id=int(app['user_id']))
            
#             # Format user data
#             user_data = {
#                 "father_name": user_details.get("father_name", "N/A"),
#                 "progress": user_details.get("progress", "N/A"),
#                 "branch": user_details.get("branch", "N/A"),
#                 "Passout_Year": user_details.get("Passout_Year", "N/A"),
#                 "Graduation_Percentage": user_details.get("Graduation_Percentage", "N/A"),
#                 "Percentage_10": user_details.get("10th_Percentage", "N/A"),
#                 "Percentage_12": user_details.get("12th_Percentage", "N/A")
#             }
            
#             job_applications.append({
#                 "id": str(app['_id']),
#                 "job_id": app['job_id'],
#                 "job_title": job.get('title', 'Unknown Position'),
#                 "user_id": app['user_id'],
#                 "user": user,
#                 "user_data": user_data,
#                 "applied_date": app.get('applied_date', datetime.now()),
#                 "status": app.get('status', 'pending')
#             })
    
#     return render(request, 'hr.html', {
#         'hr_jobs': hr_jobs,
#         'job_applications': job_applications
#     })
    
    
    

@login_required
def create_job(request):
    if request.method == 'POST':
        hr_id = request.session.get('hr_id')
        if not hr_id:
            messages.error(request, "You need to be logged in as an HR to create jobs.")
            return redirect('hr_login')
        
        # Process education data - convert list to comma-separated string
        education_input = request.POST.get('education', '')
        if isinstance(education_input, list):
            education_data = ', '.join(education_input)
        else:
            education_data = education_input
        
        # Process location data - get the first item if it's a single-item list
        locations = request.POST.getlist('locations')
        if len(locations) == 1:
            location_data = locations[0]  # Get the single location string
        else:
            location_data = ', '.join(locations)  # Join multiple locations with comma
        
        # Get form data
        job_data = {
            'Job': request.POST.get('title'),
            'Org': request.POST.get('company'),
            'Location': location_data,  # Now storing as string or comma-separated string
            'Salary': request.POST.get('salary'),
            'job_type': request.POST.get('job_type'),
            'experience': request.POST.get('experience'),
            'Skills': [skill.strip() for skill in request.POST.get('Skills', '').split(',') if skill.strip()],
            'FullDescription': request.POST.get('description'),
            'education': education_data,
            'deadline': request.POST.get('deadline'),
            'hr_id': hr_id,
            'posted_date': datetime.now(),
            'disabled': False
        }
        
        # Rest of your validation and insertion code remains the same...
        required_fields = ['Job', 'Org', 'Location', 'Salary', 'job_type', 'experience', 'FullDescription']
        for field in required_fields:
            if not job_data[field]:
                messages.error(request, f"Please fill in the {field} field.")
                return redirect('hr_panel')
        
        try:
            job_data['Salary'] = float(job_data['Salary'])
        except ValueError:
            messages.error(request, "Please enter a valid salary number.")
            return redirect('hr_panel')
        
        try:
            job_collection.insert_one(job_data)
            messages.success(request, "Job posting created successfully!")
        except Exception as e:
            messages.error(request, f"Error creating job: {str(e)}")
        
        return redirect('hr_panel')
    
    return redirect('hr_panel')
from bson import ObjectId
import datetime
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from datetime import datetime

# update the job
def update_job(request):
    if request.method == 'POST':
        hr_id = request.session.get('hr_id')
        job_id = request.POST.get('job_id')

        if not hr_id:
            messages.error(request, "You need to be logged in as an HR to update jobs.")
            return redirect('hr_login')

        if not job_id:
            messages.error(request, "Job ID is missing.")
            return redirect('hr_panel')

        try:
            job_object_id = ObjectId(job_id)
        except Exception as e:
            messages.error(request, "Invalid Job ID format.")
            return redirect('hr_panel')

        # Get existing job data
        existing_job = job_collection.find_one({"_id": job_object_id, "hr_id": hr_id})
        if not existing_job:
            messages.error(request, "You can only edit jobs that you've created.")
            return redirect('hr_panel')

        # Process locations
        locations_input = request.POST.get('locations', '[]')
        try:
            locations = json.loads(locations_input)
            if not isinstance(locations, list):
                locations = [locations] if locations else []
        except json.JSONDecodeError:
            locations = [locations_input] if locations_input else []
        
        location_data = ', '.join(locations) if len(locations) > 1 else locations[0] if locations else ''

        # Process skills
        skills_input = request.POST.get('Skills', '')
        skills = [skill.strip() for skill in skills_input.split(',') if skill.strip()]

        # Process education
        education_input = request.POST.get('education', '')
        education_items = [item.strip() for item in education_input.split(',') if item.strip()]
        education_data = ', '.join(education_items) if education_items else ''

        # Update job data
        update_data = {
            'Job': request.POST.get('title', existing_job.get('Job')),
            'Org': request.POST.get('company', existing_job.get('Org')),
            'Location': location_data,
            'Salary': request.POST.get('salary', existing_job.get('Salary')),
            'job_type': request.POST.get('job_type', existing_job.get('job_type')),
            'experience': request.POST.get('experience', existing_job.get('experience')),
            'Skills': skills,
            'FullDescription': request.POST.get('description', existing_job.get('FullDescription')),
            'education': education_data,
            'deadline': request.POST.get('deadline', existing_job.get('deadline')),
            'updated_at': datetime.now()
        }

        job_collection.update_one({"_id": job_object_id}, {"$set": update_data})
        messages.success(request, "Job posting updated successfully!")
        return redirect('hr_panel')

    return redirect('hr_panel')

from django.shortcuts import render
def demo_hr_panel(request):
    # Fetch the latest 6 jobs from MongoDB
    try:
        hr_jobs_cursor = job_collection.find({"disabled": False}).sort("posted_date", -1).limit(6)
        hr_jobs = []
        
        for job in hr_jobs_cursor:
            job['_id'] = str(job['_id'])  # Convert ObjectId to string
            
            # Fix location format if it's stored as ["location1,location2"]
            if isinstance(job.get('Location'), str) and job['Location'].startswith('['):
                # Remove brackets and quotes, then split by comma
                locations = job['Location'][2:-2].replace('"', '').split(',')
                job['Location'] = ', '.join(locations)
            # If it's already in correct format, leave as is
            elif isinstance(job.get('Location'), str):
                job['Location'] = job['Location']
            # If it's a list, join with commas
            elif isinstance(job.get('Location'), list):
                job['Location'] = ', '.join(job['Location'])
            
            hr_jobs.append(job)
        
        context = {
            'hr_jobs': hr_jobs,
        }
        return render(request, 'demo_hr_panel.html', context)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    

from django.shortcuts import render

def demo_hr_dashboard(request):
    return render(request, 'demo_hr_dashboard.html')
from django.http import JsonResponse
from bson import ObjectId

def get_job_data(request, job_id):
    try:
        job_object_id = ObjectId(job_id)
        job = job_collection.find_one({"_id": job_object_id})
        if job:
            job['_id'] = str(job['_id'])  # Convert ObjectId to string
            return JsonResponse(job)
        else:
            return JsonResponse({"error": "Job not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from bson import ObjectId
# delete jobs
# @login_required
# def delete_job(request):
#     if request.method == 'POST':
#         hr_id = request.session.get('hr_id')
#         job_id = request.POST.get('job_id')  # Ensure this matches the form field name
#         print(f"HR ID: {hr_id}")
#         print(f"Job ID from form: {job_id}")
        
#         if not hr_id:
#             messages.error(request, "You need to be logged in as an HR to delete jobs.")
#             return redirect('hr_login')
        
#         if not job_id:
#             messages.error(request, "No job ID provided for deletion.")
#             return redirect('hr_panel')
            
#         try:
#             # Convert job_id to ObjectId for MongoDB query
#             job_id_obj = ObjectId(job_id)
#             print(f"Successfully converted to ObjectId: {job_id_obj}")
            
#             # Check if the job belongs to this HR
#             job = job_collection.find_one({"_id": job_id_obj, "hr_id": hr_id})
#             print(f"Job found: {job is not None}")
            
#             if not job:
#                 messages.error(request, "You can only delete jobs that you've created.")
#                 return redirect('hr_panel')
            
#             # Delete job
#             result = job_collection.delete_one({"_id": job_id_obj})
#             print(f"Delete result: {result.deleted_count} document(s) deleted")
            
#             # Delete related applications
#             app_result = job_applied_collection.delete_many({"job_id": str(job_id_obj)})
#             print(f"Applications deleted: {app_result.deleted_count}")
            
#             messages.success(request, "Job posting and related applications deleted successfully!")
#         except Exception as e:
#             messages.error(request, f"Error deleting job: {str(e)}")
#             print(f"Error in delete_job: {str(e)}")
        
#         return redirect('hr_panel')
    
#     return redirect('hr_panel')



@login_required
def delete_job(request):
    if request.method == 'POST':
        hr_id = request.session.get('hr_id')
        job_id = request.POST.get('job_id')  # Ensure this matches the form field name
        print(f"HR ID: {hr_id}")
        print(f"Job ID from form: {job_id}")
        
        if not hr_id:
            messages.error(request, "You need to be logged in as an HR to delete jobs.")
            return redirect('hr_login')
        
        if not job_id:
            messages.error(request, "No job ID provided for deletion.")
            return redirect('hr_panel')
            
        try:
            # Convert job_id to ObjectId for MongoDB query
            job_id_obj = ObjectId(job_id)
            print(f"Successfully converted to ObjectId: {job_id_obj}")
            
            # Check if the job belongs to this HR
            job = job_collection.find_one({"_id": job_id_obj, "hr_id": hr_id})
            print(f"Job found: {job is not None}")
            
            if not job:
                messages.error(request, "You can only delete jobs that you've created.")
                return redirect('hr_panel')
            
            # Update job to set disabled=True instead of deleting
            result = job_collection.update_one(
                {"_id": job_id_obj},
                {"$set": {"disabled": True}}
            )
            print(f"Update result: {result.modified_count} document(s) updated")
            
            # Optionally, you can also mark related applications as disabled
            app_result = job_applied_collection.update_many(
                {"job_id": str(job_id_obj)},
                {"$set": {"disabled": True}}
            )
            print(f"Applications updated: {app_result.modified_count}")
            
            messages.success(request, "Job posting has been disabled successfully!")
        except Exception as e:
            messages.error(request, f"Error disabling job: {str(e)}")
            print(f"Error in delete_job: {str(e)}")
        
        return redirect('hr_panel')
    
    return redirect('hr_panel')




def toggle_job_status(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            job_id = data.get('job_id')
            disable = data.get('disable', True)
            hr_id = request.session.get('hr_id')

            if not hr_id:
                return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)

            job = job_collection.find_one({"_id": ObjectId(job_id), "hr_id": hr_id})
            if not job:
                return JsonResponse({'success': False, 'error': 'Job not found or not authorized'}, status=404)

            # Update the disabled status
            job_collection.update_one(
                {"_id": ObjectId(job_id)},
                {"$set": {"disabled": disable}}
            )

            return JsonResponse({'success': True})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'}, status=400)
# Get job details for editing
from django.http import JsonResponse
from bson import ObjectId
import re

def clean_education_list(education_list):
    # Remove extra spaces between letters using regex
    return [re.sub(r'\s+', ' ', edu.strip()) for edu in education_list]


def get_job_details(request, job_id):
    hr_id = request.session.get('hr_id')
    
    if not hr_id:
        return JsonResponse({"error": "Not authorized"}, status=401)
    
    try:
        job = job_collection.find_one({"_id": ObjectId(job_id), "hr_id": hr_id})
        
        if not job:
            return JsonResponse({"error": "Job not found or not authorized"}, status=404)
        
        job['_id'] = str(job['_id'])

        # ✅ Fix the education field if it exists and is a list
        if 'education' in job and isinstance(job['education'], list):
            job['education'] = clean_education_list(job['education'])

        print(f"Job data: {job}")  # Debugging line
        
        return JsonResponse(job)
    except Exception as e:
        print(f"Error fetching job details: {e}")
        return JsonResponse({"error": "Invalid Job ID format or server error"}, status=500)

# Update application status
@login_required
def update_application_status(request):
    if request.method == 'POST':
        hr_id = request.session.get('hr_id')
        application_id = request.POST.get('application_id')
        status = request.POST.get('status')
        
        if not hr_id:
            return JsonResponse({"error": "Not authorized"}, status=401)
        
        # Update application status
        application = job_applied_collection.find_one({"_id": ObjectId(application_id)})
        
        if not application:
            return JsonResponse({"error": "Application not found"}, status=404)
        
        # Check if the job belongs to this HR
        job = job_collection.find_one({"_id": ObjectId(application['job_id']), "hr_id": hr_id})
        
        if not job:
            return JsonResponse({"error": "Not authorized to update this application"}, status=401)
        
        # Update status
        job_applied_collection.update_one(
            {"_id": ObjectId(application_id)},
            {"$set": {"status": status, "updated_at": datetime.now()}}
        )
        
        return JsonResponse({"success": True, "message": f"Application marked as {status}"})
    
    return JsonResponse({"error": "Method not allowed"}, status=405)



# HR logout
# def hr_logout(request):
#     logout(request)
#     if 'hr_username' in request.session:
#         del request.session['hr_username']
#     if 'hr_id' in request.session:
#         del request.session['hr_id']
#     return redirect('hr_login')



# Hr panel
from bson import ObjectId
from django.shortcuts import render, redirect
from django.http import JsonResponse
import re

def hr_panel_view(request):
    if not request.session.get('hr_id'):
        return redirect('loginhr')

    hr_id = request.session.get('hr_id')
    hr_user = hr_collection.find_one({"_id": ObjectId(hr_id)})
    is_active = hr_user.get('is_active') if hr_user else False
    
    # Fetch jobs created by this HR, sorted by posted_date in descending order (newest first)
    hr_jobs = list(job_collection.find({"hr_id": hr_id}).sort("posted_date", -1))
    
    # Calculate applicants_count for each job
    for job in hr_jobs:
        job_id_str = str(job['_id'])
        job['job_id'] = job_id_str
        job['id'] = job_id_str 
        applicants_count = job_applied_collection.count_documents({"job_id": ObjectId(job_id_str)})
        job['applicants_count'] = applicants_count
        
    for job in hr_jobs:
       if 'education' in job:
            # If education is stored as a list, convert to comma-separated string
            if isinstance(job['education'], list):
                job['education'] = ', '.join(job['education'])
            # If it's already a string but contains brackets/quotes, clean it
            elif isinstance(job['education'], str):
                # Remove brackets and quotes if present
                job['education'] = job['education'].replace('[','').replace(']','').replace('"','')
    
    # Process location - updated version
    for job in hr_jobs:
      if 'Location' in job:
        loc = job['Location']
        if isinstance(loc, str):
            # Handle string that looks like a list (e.g., '["Bengaluru","Bihar"]')
            if loc.startswith('[') and loc.endswith(']'):
                loc = loc[1:-1].split(',')
            else:
                loc = [loc]
        elif isinstance(loc, list):
            pass  # already a list
        else:
            loc = [str(loc)]

        # Clean each location by removing any quotes or extra spaces
        clean_locations = [str(l).strip().strip('"').strip("'") for l in loc]
        job['Location'] = ', '.join(clean_locations)

    # Preprocess skills
    for job in hr_jobs:
        if 'Skills' in job:
            if isinstance(job['Skills'], str):
                skills_list = job['Skills'].split(',')
                skills_list = [skill.strip() for skill in skills_list]
                job['Skills'] = skills_list
            job['Skills'] = [re.sub(r'\s+', '', skill) for skill in job['Skills']]
    
    # Get all job IDs
    job_ids = [str(job['_id']) for job in hr_jobs]
    
    # Get applications for these jobs
    applications = list(job_applied_collection.find({"job_id": {"$in": [ObjectId(id) for id in job_ids]}}))
    
    # Process applicants
    applicants = []
    for application in applications:
        user_id = application.get('user_id')
        if user_id:
            user_data = auth_user_collection.find_one({"_id": ObjectId(user_id)})
            if user_data:
                user_data['application_id'] = str(application['_id'])
                user_data['applied_job_id'] = str(application['job_id'])
                user_data['applied_at'] = application.get('applied_at', 'N/A')
                job = next((j for j in hr_jobs if str(j['_id']) == str(application['job_id'])), None)
                user_data['applied_job_title'] = job['Job'] if job else 'Unknown Job'
                user_data['applicant_id'] = str(user_data['_id'])
                if '_id' in user_data:
                    del user_data['_id']
                applicants.append(user_data)
    
    # Count total employees (users in auth_user collection)
    total_employees = auth_user_collection.count_documents({})
    
    context = {
        'hr_jobs': hr_jobs,
        'applicants': applicants,
        'is_active': is_active,
        'total_employees': total_employees
    }

    return render(request, 'hr.html', context)

# Add a view to get user details
def get_applicant_details(request, user_id):
    if not request.session.get('hr_id'):
        return JsonResponse({"error": "Not authorized"}, status=403)
    print(f"Fetching details for user_id for view details: {user_id}")

    user_data = auth_user_collection.find_one({"_id": ObjectId(user_id)})
    
    if not user_data:
        return JsonResponse({"error": "User not found"}, status=404)
    
    # ✅ Process location like in hr_panel_view()
    loc = user_data.get('location', 'N/A')
    if isinstance(loc, str):
        # Handle string that looks like a list (e.g., '["Bengaluru","Bihar"]')
        if loc.startswith('[') and loc.endswith(']'):
            loc = loc[1:-1].split(',')
        else:
            loc = [loc]
    elif isinstance(loc, list):
        pass  # already a list
    else:
        loc = [str(loc)]
    
    # Clean each location by removing any quotes or extra spaces
    clean_locations = [str(l).strip().strip('"').strip("'") for l in loc]
    formatted_location = ', '.join(clean_locations)

    # ✅ Process skills (similar to hr_panel_view)
    skills = user_data.get('skills', [])
    if isinstance(skills, str):
        skills = [skill.strip() for skill in skills.split(',')]
    elif not isinstance(skills, list):
        skills = []

    # Process user data for response
    user_details = {
        "user_id": user_id,
        "username": user_data.get("username", "N/A"),
        "email": user_data.get("email", "N/A"),
        "father_name": user_data.get("father_name", "N/A"),
        "mobile": user_data.get("mobile", "N/A"),
        "location": formatted_location,  # Cleaned location
        "branch": user_data.get("branch", "N/A"),
        "ug_college": user_data.get("ug_college", "N/A"),
        "Passout_Year": user_data.get("Passout_Year", "N/A"),
        "Graduation_Percentage": user_data.get("Graduation_Percentage", "N/A"),
        "10th_Percentage": user_data.get("10th_Percentage", "N/A"),
        "12th_Percentage": user_data.get("12th_Percentage", "N/A"),
        "skills" :user_data.get('skills', []), # Comma-separated skills
        "profile_picture": user_data.get("profile_picture", None)
    }
    
    return JsonResponse({"success": True, "data": user_details})
# hr user list
def hr_userlist(request):
    if not request.session.get('hr_id'):
        return redirect('loginhr')
    
    # Get filter parameters from request
    skills = request.GET.getlist('skills', [])
    graduation_year = request.GET.get('graduation_year', '')
    location = request.GET.get('location', '')
    min_percentage = request.GET.get('min_percentage', '')
    search = request.GET.get('search', '')
    
    query = {}
    
    # Handle skills filter - users must have ALL selected skills
    if skills:
        # Convert skills to regex patterns for case-insensitive matching
        skills_regex = [{'$regex': f'^{re.escape(skill)}', '$options': 'i'} for skill in skills]
        query['skills'] = {'$all': skills_regex}
    
    # Other filters remain the same
    if graduation_year:
        query['graduation_year'] = graduation_year
    
    if location:
        query['location'] = {'$regex': location, '$options': 'i'}
    
    if min_percentage:
        query['Graduation_Percentage'] = {'$gte': float(min_percentage)}
    
    if search:
        query['$or'] = [
            {'first_name': {'$regex': search, '$options': 'i'}},
            {'last_name': {'$regex': search, '$options': 'i'}},
            {'email': {'$regex': search, '$options': 'i'}},
            {'username': {'$regex': search, '$options': 'i'}}
        ]
    
    users = list(auth_user_collection.find(query))
    hr_id = request.session.get('hr_id')
    hr_user = hr_collection.find_one({"_id": ObjectId(hr_id)})
    is_active = hr_user.get('is_active') if hr_user else False
    
    return render(request, 'hr_userlist.html', {'users': users, 'hr_id': hr_id, 'is_active': is_active})
def get_suggestions(request):
    if request.method == 'GET':
        query = request.GET.get('query', '')
        type_ = request.GET.get('type', '')
        print(f"Received request for {type_} suggestions with query: {query}")  # Debugging
        
        if type_ == 'location':
            suggestions = list(location_collection.find(
                {"name": {"$regex": f"^{query}", "$options": "i"}},
                {"_id": 0, "name": 1}
            ).limit(10))
            suggestions = [item['name'] for item in suggestions]
        elif type_ == 'skill':
            suggestions = list(skills_collection.find(
                {"name": {"$regex": f"^{query}", "$options": "i"}},
                {"_id": 0, "name": 1}
            ).limit(10))
            suggestions = [item['name'] for item in suggestions]
        else:
            suggestions = []
            
        print(f"Returning suggestions: {suggestions}")  # Debugging
        return JsonResponse({'suggestions': suggestions})
    return JsonResponse({'suggestions': []})

def get_skills(request):
    search_term = request.GET.get('search', '').strip()
    
    # Create a case-insensitive regex pattern if search term exists
    query = {}
    if search_term:
        query['name'] = {
            '$regex': f'.*{re.escape(search_term)}.*',  # Changed to search anywhere in the string
            '$options': 'i'
        }
    
    # Fetch skills with projection and sort alphabetically
    skills = list(skills_collection.find(query, {'name': 1, '_id': 0})
                         .sort('name', 1)  # Sort alphabetically
                         .limit(20))
    
    return JsonResponse({
        'success': True,
        'skills': [skill['name'] for skill in skills]
    })

# API endpoint to get detailed user information
from bson import ObjectId
from django.http import JsonResponse

from bson import ObjectId
from django.http import JsonResponse
def get_user_details(request, user_id):
    if not request.session.get('hr_id'):
        return JsonResponse({'error': 'Not authorized'}, status=401)
    
    try:
        user_id = int(user_id)
    except ValueError:
        return JsonResponse({"error": "Invalid user ID format"}, status=400)
    
    user_data = auth_user_collection.find_one({"id": user_id})

    if not user_data:
        return JsonResponse({"error": "User not found"}, status=404)
    
    # Check if resume exists in filesystem
    resume_filename = f"resume_{user_id}.pdf"
    resume_path = os.path.join(settings.MEDIA_ROOT, 'resumes', resume_filename)
    has_resume = os.path.exists(resume_path)
    
    # If using MongoDB GridFS, you could check like this:
    # has_resume = fs.exists({"filename": resume_filename})
    
    user_details = {
        "user_id": user_data["id"],
        "username": user_data.get("username", "N/A"),
        "email": user_data.get("email", "N/A"),
        "father_name": user_data.get("father_name", "N/A"),
        "mobile": user_data.get("mobile", "N/A"),
        "location": user_data.get("location", "N/A"),
        "branch": user_data.get("branch", "N/A"),
        "ug_college": user_data.get("ug_college", "N/A"),
        "Passout_Year": user_data.get("Passout_Year", "N/A"),
        "Graduation_Percentage": user_data.get("Graduation_Percentage", "N/A"),
        "10th_Percentage": user_data.get("10th_Percentage", "N/A"),
        "12th_Percentage": user_data.get("12th_Percentage", "N/A"),
        "skills": user_data.get("skills", []),
        "profile_picture": user_data.get("profile_picture", None),
        "has_resume": has_resume,  # Add this flag
        "resume_filename": resume_filename if has_resume else None
    }
    
    return JsonResponse({"success": True, "data": user_details})

  
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings

def contact_applicant(request):
    if not request.session.get('hr_id'):
        return redirect('loginhr')
    
    if request.method == 'POST':
        applicant_email = request.POST.get('applicant_email')
        subject = request.POST.get('email_subject')
        message = request.POST.get('email_message')
        
        if not all([applicant_email, subject, message]):
            messages.error(request, 'All fields are required.')
            return redirect('hr_panel')
        
        # Get HR details for the 'from' email
        hr_id = request.session.get('hr_id')
        hr_data = hr_collection.find_one({"_id": ObjectId(hr_id)})
        hr_email = hr_data.get('email', settings.DEFAULT_FROM_EMAIL)
        
        try:
            send_mail(
                subject,
                message,
                hr_email,  # From email
                [applicant_email],  # To email
                fail_silently=False,
            )
            messages.success(request, f'Message sent successfully to {applicant_email}')
        except Exception as e:
            messages.error(request, f'Failed to send message: {str(e)}')
        
        return redirect('hr_panel')
   
   
   
   
   
   
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from datetime import datetime, timedelta
from bson import json_util
import os
from django.conf import settings

# In-memory collection to store jobs
apijob_collection = db1["apijob"]

# Track last cleanup time
last_cleanup_time = None

import os
from django.conf import settings

@csrf_exempt
def store_jobs(request):
    global last_cleanup_time
    
    if request.method == 'POST':
        try:
            current_time = datetime.now()
            
            # Cleanup old data if needed
            if last_cleanup_time is None or (current_time - last_cleanup_time) >= timedelta(minutes=14390):
                apijob_collection.delete_many({})
                last_cleanup_time = current_time
                print(f"Performed cleanup at {current_time}")

            data = json.loads(request.body)
            jobs = data.get('jobs', [])

            if not jobs:
                return JsonResponse({'status': 'error', 'message': 'No jobs provided'}, status=400)

            # Insert jobs into MongoDB
            result = apijob_collection.insert_many(jobs)
            inserted_ids = result.inserted_ids
            inserted_jobs = list(apijob_collection.find({'_id': {'$in': inserted_ids}}))
            
            # Prepare data for JSON file
            output_data = {
                'timestamp': current_time.isoformat(),
                'inserted_count': len(inserted_ids),
                'jobs': inserted_jobs
            }
            
            # Convert ObjectId to string for JSON serialization
            for job in output_data['jobs']:
                job['_id'] = str(job['_id'])
            
            # Create storage directory if it doesn't exist
            storage_dir = os.path.join(settings.BASE_DIR, 'job_storage')
            os.makedirs(storage_dir, exist_ok=True)
            
            # Generate filename with timestamp
            filename = f"jobs_{current_time.strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(storage_dir, filename)
            
            # Write to JSON file
            with open(filepath, 'w') as f:
                json.dump(output_data, f, indent=2, default=json_util.default)
            
            return JsonResponse({
                'status': 'success', 
                'message': f'{len(inserted_ids)} jobs stored successfully',
                'file_path': filepath,
                'inserted_count': len(inserted_ids),
                'timestamp': current_time.isoformat()
            })

        except Exception as e:
            return JsonResponse({
                'status': 'error', 
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            }, status=400)

    return JsonResponse({
        'status': 'error', 
        'message': 'Invalid request method',
        'timestamp': datetime.now().isoformat()
    }, status=405)

@csrf_exempt
def get_jobs(request):
    if request.method == 'GET':
        try:
            # Get all jobs from collection (no pagination for now)
            jobs = list(apijob_collection.find())
            
            # Convert ObjectId to string for JSON serialization
            for job in jobs:
                job['_id'] = str(job['_id'])
            
            return JsonResponse({
                'status': 'success',
                'data': jobs,
                'count': len(jobs)
            }, json_dumps_params={'default': json_util.default})
            
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)
from django.http import FileResponse, Http404
import os
from django.conf import settings

from django.http import JsonResponse, FileResponse
import os
from django.conf import settings

def download_resume(request, user_id):
    print("hi downloading resume")
    if not request.session.get('hr_id'):
        return JsonResponse({'error': 'Not authorized'}, status=401)
    
    try:
        user_id = int(user_id)
    except ValueError:
        return JsonResponse({"error": "Invalid user ID format"}, status=400)
    
    # Fetch user from the MongoDB collection
# adjust the import path as needed
    user = auth_user_collection.find_one({"id": user_id})
    
    if not user:
        return JsonResponse({"error": "User not found"}, status=404)
    
    username = user.get("username")
    if not username:
        return JsonResponse({"error": "Username not available"}, status=500)
    
    resume_filename = f"resume_{user_id}.pdf"
    resume_path = os.path.join(settings.MEDIA_ROOT, 'resumes', resume_filename)
    
    if not os.path.exists(resume_path):
        return JsonResponse({"error": "Resume not found"}, status=404)
    
    try:
        file = open(resume_path, 'rb')
        response = FileResponse(file)
        response['Content-Disposition'] = f'attachment; filename="{username}.pdf"'
        response['Content-Type'] = 'application/pdf'
        return response
    except Exception as e:
        return JsonResponse({"error": f"Error accessing resume: {str(e)}"}, status=500)

from django.http import JsonResponse
from django.conf import settings

def get_api_keys(request):
    print(f"RAPIDAPI_KEY: {settings.RAPIDAPI_KEY}")
    print(f"RAPIDAPI_HOST: {settings.RAPIDAPI_HOST}")
    return JsonResponse({
        "RAPIDAPI_KEY": settings.RAPIDAPI_KEY,
        "RAPIDAPI_HOST": settings.RAPIDAPI_HOST
    })
    
from django.http import JsonResponse

def get_api_keys_message(request):
    print(f"RAPIDAPI_KEY: {settings.RAPIDAPI_KEY}")
    print(f"RAPIDAPI_HOST: {settings.RAPIDAPI_HOST}")
    return JsonResponse({
        "serviceID": settings.SERVICE_ID,  # Use correctly loaded variables
        "templateID": settings.TEMPLATE_ID,
    })


import re
from django.http import JsonResponse

def get_locations(request):
    search_term = request.GET.get('search', '').strip().lower()
    
    query = {}
    if search_term:
        query["locations"] = {
            "$regex": f".*{re.escape(search_term)}.*",
            "$options": "i"
        }
    
    docs = list(location_collection.find(query, {"_id": 0, "locations": 1}))
    
    location_names = []
    for doc in docs:
        if "locations" in doc:
            location_names.extend([loc for loc in doc["locations"] if search_term in loc.lower()])
    
    unique_locations = sorted(list(set(location_names)))
    
    return JsonResponse({
        "success": True,
        "locations": unique_locations
    })
import re
from django.http import JsonResponse

def get_education(request):
    search_term = request.GET.get('search', '').strip().lower()
    print(f"Search term for education: {search_term}")

    doc = education_collection.find_one({}, {"_id": 0, "education": 1})
    print(f"Doc fetched: {doc}")

    education_names = []
    if doc and "education" in doc:
        education_names = [
            edu for edu in doc["education"]
            if search_term in edu.lower()
        ]

    unique_education = sorted(list(set(education_names)), key=lambda x: x.lower())
    print(f"Unique education names: {unique_education}")

    return JsonResponse({
        "success": True,
        "education": unique_education
    })


def search_locations(request):
    search_term = request.GET.get('search', '').strip().lower()
    country_filter = request.GET.get('country', '').strip()
    state_filter = request.GET.get('state', '').strip()
    
    # Build the query based on filters
    query = {}
    if country_filter:
        query['location.country'] = country_filter
    if state_filter:
        query['location.state'] = state_filter
    
    # Search across all location fields
    if search_term:
        query['$or'] = [
            {'location.country': {'$regex': search_term, '$options': 'i'}},
            {'location.state': {'$regex': search_term, '$options': 'i'}},
            {'location.city': {'$regex': search_term, '$options': 'i'}}
        ]
    
    # Get matching locations
    locations = list(auth_user_collection.find(query, {
        'location.country': 1,
        'location.state': 1,
        'location.city': 1,
        '_id': 0
    }).limit(20))
    
    # Remove duplicates and empty values
    unique_locations = []
    seen = set()
    
    for loc in locations:
        if 'location' in loc:
            loc_data = loc['location']
            loc_key = (loc_data.get('country'), loc_data.get('state'), loc_data.get('city'))
            if loc_key not in seen:
                seen.add(loc_key)
                unique_locations.append({
                    'country': loc_data.get('country'),
                    'state': loc_data.get('state'),
                    'city': loc_data.get('city')
                })
    
    return JsonResponse({
        'success': True,
        'locations': unique_locations
    })
    
    
from django.shortcuts import render, get_object_or_404
from bson import ObjectId
from django.core.paginator import Paginator

def job_applicants(request, job_id):
    # Get the job details
    hr_id = request.session.get('hr_id')
    hr_user = hr_collection.find_one({"_id": ObjectId(hr_id)})
    is_active = hr_user.get('is_active') if hr_user else False
    
    job = job_collection.find_one({"_id": ObjectId(job_id)})
    if not job:
        return render(request, '404.html', status=404)
 
    # Convert ObjectId to string for template
    job['id'] = str(job['_id'])

    # ✅ Fix: Convert comma-separated skill string into list
    if isinstance(job.get('Skills'), str):
        job['Skills'] = [skill.strip() for skill in job['Skills'].split(',')]

    # ✅ Process job location to clean format
    if 'Location' in job:
        loc = job['Location']
        if isinstance(loc, str):
            # Handle string that looks like a list (e.g., '["Bengaluru","West Bengal"]')
            if loc.startswith('[') and loc.endswith(']'):
                loc = loc[1:-1].split(',')
                loc = [l.strip().strip('"').strip("'") for l in loc]
                job['Location'] = ', '.join(loc)
            else:
                job['Location'] = loc
        elif isinstance(loc, list):
            job['Location'] = ', '.join([str(l).strip().strip('"').strip("'") for l in loc])

    # ✅ Process education to clean format
    if 'education' in job:
        edu = job['education']
        if isinstance(edu, str):
            # Handle string that looks like a list (e.g., '["10th Grade","Bachelor of Engineering (B.E.)"]')
            if edu.startswith('[') and edu.endswith(']'):
                edu = edu[1:-1].split(',')
                edu = [e.strip().strip('"').strip("'") for e in edu]
                job['education'] = ', '.join(edu)
            else:
                job['education'] = edu
        elif isinstance(edu, list):
            job['education'] = ', '.join([str(e).strip().strip('"').strip("'") for e in edu])
    if 'education' in job:
        edu = job['education']
        if isinstance(edu, str):
            if edu.startswith('[') and edu.endswith(']'):
                # Handle JSON-like array string
                edu = edu[1:-1].split(',')
                edu = [e.strip().strip('"').strip("'") for e in edu]
                job['education_list'] = edu
            else:
                # Handle comma-separated string
                job['education_list'] = [e.strip() for e in edu.split(',')]
        elif isinstance(edu, list):
            job['education_list'] = edu
        else:
            job['education_list'] = [str(edu)]
    # Get all applicants for this job
    applications = list(job_applied_collection.find({"job_id": job_id}))

    applicants = []
    for application in applications:
        user_id = application.get('user_id')
        if user_id:
            user_data = auth_user_collection.find_one({"_id": ObjectId(user_id)})
            if user_data:
                # Process location
                loc = user_data.get('location', 'N/A')
                if isinstance(loc, str):
                    if loc.startswith('[') and loc.endswith(']'):
                        loc = loc[1:-1].split(',')
                    else:
                        loc = [loc]
                elif isinstance(loc, list):
                    pass  # already a list
                else:
                    loc = [str(loc)]
                
                clean_locations = [str(l).strip().strip('"').strip("'") for l in loc]
                formatted_location = ', '.join(clean_locations)
               
                # Process skills
                skills = user_data.get('skills', [])
                if isinstance(skills, str):
                    skills = [skill.strip() for skill in skills.split(',')]
                elif not isinstance(skills, list):
                    skills = []

                # Prepare applicant data
                applicant = {
                    'applicant_id': str(user_data['_id']),
                    'username': user_data.get('username', 'N/A'),
                    'email': user_data.get('email', 'N/A'),
                    'mobile': user_data.get('mobile', 'N/A'),
                    'location': formatted_location,
                    'branch': user_data.get('branch', 'N/A'),
                    'ug_college': user_data.get('ug_college', 'N/A'),
                    'skills': user_data.get('skills', []),
                    'profile_picture': user_data.get('profile_picture'),
                    'applied_at': application.get('applied_at', 'N/A'),
                    'Graduation_Percentage': user_data.get('Graduation_Percentage', 'N/A'),
                    'Passout_Year': user_data.get('Passout_Year', 'N/A'),
                    '10th_Percentage': user_data.get('10th_Percentage', 'N/A'),
                    '12th_Percentage': user_data.get('12th_Percentage', 'N/A'),
                    'father_name': user_data.get('father_name', 'N/A')
                }
                applicants.append(applicant)
   
    # Pagination
    paginator = Paginator(applicants, 10)  # Show 10 applicants per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'job': job,
        'applicants': page_obj,
        'applicants_count': len(applicants),
        'is_active': is_active,
    } 
    print(f"Job ID: {job_id}, Applicants Count: {len(applicants)}")

    return render(request, 'job_applicants.html', context)
# views.py
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from bson import ObjectId
import re
import base64
import json
from datetime import datetime

@csrf_exempt
def hr_profile_view(request):
    if not request.session.get('hr_id'):
        return redirect('loginhr')
    
    hr_id = request.session['hr_id']
    
    if request.method == 'GET':
        # Fetch HR profile data
        hr_profile = hr_collection.find_one({"_id": ObjectId(hr_id)})
        
        if not hr_profile:
            return JsonResponse({'success': False, 'message': 'HR profile not found'}, status=404)
        
        # Prepare response data
        response_data = {
            'success': True,
            'data': {
                'user_name': hr_profile.get('hrname', ''),
                'email': hr_profile.get('email', ''),
                'mobile': hr_profile.get('mobile', ''),
                'linkedin': hr_profile.get('linkedin', ''),
                'profile_picture': hr_profile.get('profile_picture', ''),
                'company_name': hr_profile.get('company_name', ''),
                'company_email': hr_profile.get('company_email', ''),
                'company_website': hr_profile.get('company_website', ''),
                'company_industry': hr_profile.get('company_industry', ''),
                'company_size': hr_profile.get('company_size', ''),
                'company_description': hr_profile.get('company_description', ''),
                'hr_position': hr_profile.get('position', ''),
                'hr_department': hr_profile.get('department', ''),
                'hr_certification': hr_profile.get('certification', ''),
                'certification_year': hr_profile.get('certification_year', ''),
                'hr_specialization': hr_profile.get('specialization', ''),
                'is_active': hr_profile.get('is_active'),  # ✅ Added this line
                'jobs_posted': job_collection.count_documents({"hr_id": hr_id}),
                

                'candidates_reviewed': 0,  # You'll need to implement this
                'interviews_scheduled': 0  # You'll need to implement this
            }
        }
        print(f"is_active: {response_data['data']['is_active']}")  # Debugging line
        return JsonResponse(response_data)
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            update_type = data.get('type')
            
            update_data = {}
            
            if update_type == 'personal_info':
                update_data = {
                    'name': data.get('username'),
                    'mobile': data.get('mobile'),
                    'linkedin': data.get('linkedin')
                }
            elif update_type == 'company_info':
                update_data = {
                    'company_name': data.get('company_name'),
                    'company_email': data.get('company_email'),
                    'company_website': data.get('company_website'),
                    'company_industry': data.get('company_industry'),
                    'company_size': data.get('company_size'),
                    'company_description': data.get('company_description')
                }
            elif update_type == 'hr_details':
                update_data = {
                    'position': data.get('hr_position'),
                    'department': data.get('hr_department'),
                    'certification': data.get('hr_certification'),
                    'certification_year': data.get('certification_year'),
                    'specialization': data.get('hr_specialization')
                }
            
            # Update the HR profile
            result = hr_collection.update_one(
                {"_id": ObjectId(hr_id)},
                {"$set": update_data}
            )
            
            if result.modified_count > 0:
                return JsonResponse({'success': True, 'message': 'Profile updated successfully'})
            else:
                return JsonResponse({'success': False, 'message': 'No changes made'})
                
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)


@csrf_exempt
def upload_profile_picture(request):
    if not request.session.get('hr_id'):
        return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)
    
    if request.method == 'POST' and request.FILES.get('profile_picture'):
        hr_id = request.session['hr_id']
        file = request.FILES['profile_picture']
        
        try:
            # Save the file
            file_name = f"hr_profile_{hr_id}_{file.name}"
            file_path = default_storage.save(f"profile_pictures/{file_name}", ContentFile(file.read()))
            
            # For MongoDB, you might want to store the file data directly
            with default_storage.open(file_path) as f:
                file_data = f.read()
                encoded_data = base64.b64encode(file_data).decode('utf-8')
                
                # Update HR profile with picture
                hr_collection.update_one(
                    {"_id": ObjectId(hr_id)},
                    {"$set": {"profile_picture": encoded_data}}
                )
            
            return JsonResponse({
                'success': True,
                'message': 'Profile picture updated',
                'image_url': f"/media/{file_path}"  # Adjust based on your media URL config
            })
            
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)





from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from bson import ObjectId
import base64
from datetime import datetime

@csrf_exempt
def upload_company_logo(request):
    if not request.session.get('hr_id'):
        return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)
    
    if request.method == 'POST' and request.FILES.get('company_logo'):
        hr_id = request.session['hr_id']
        file = request.FILES['company_logo']
        
        try:
            # Read and encode the file
            file_data = file.read()
            encoded_data = base64.b64encode(file_data).decode('utf-8')
            
            # Get file content type
            content_type = file.content_type
            
            # Update HR profile with logo
            result = hr_collection.update_one(
                {"_id": ObjectId(hr_id)},
                {
                    "$set": {
                        "company_logo": encoded_data,
                        "company_logo_content_type": content_type,
                        "updated_at": datetime.now()
                    }
                }
            )
            
            if result.modified_count > 0:
                return JsonResponse({
                    'success': True,
                    'message': 'Company logo updated',
                    'logo_url': f"data:{content_type};base64,{encoded_data}"
                })
            return JsonResponse({'success': False, 'message': 'Failed to update logo'})
                
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

@csrf_exempt
def upload_verification_documents(request):
    if not request.session.get('hr_id'):
        return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)
    
    if request.method == 'POST':
        hr_id = request.session['hr_id']
        update_data = {
            "updated_at": datetime.now()
        }
        
        try:
            # Handle HR ID Proof
            if 'hr_id_proof' in request.FILES:
                file = request.FILES['hr_id_proof']
                file_data = file.read()
                update_data['hr_id_proof'] = base64.b64encode(file_data).decode('utf-8')
                update_data['hr_id_proof_content_type'] = file.content_type
                update_data['verification_status.hr_identity_verified'] = False
            
            # Handle Company Authorization
            if 'company_authorization' in request.FILES:
                file = request.FILES['company_authorization']
                file_data = file.read()
                update_data['company_authorization'] = base64.b64encode(file_data).decode('utf-8')
                update_data['company_authorization_content_type'] = file.content_type
                update_data['verification_status.company_verified'] = False
            
            if len(update_data) > 1:  # More than just updated_at
                result = hr_collection.update_one(
                    {"_id": ObjectId(hr_id)},
                    {"$set": update_data}
                )
                
                if result.modified_count > 0:
                    return JsonResponse({
                        'success': True,
                        'message': 'Documents uploaded successfully. Verification pending.'
                    })
                return JsonResponse({'success': False, 'message': 'Failed to update documents'})
            return JsonResponse({'success': False, 'message': 'No documents provided'})
                
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

def get_document(request, doc_type):
    if not request.session.get('hr_id'):
        return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)
    
    hr_id = request.session['hr_id']
    valid_types = ['company_logo', 'hr_id_proof', 'company_authorization']
    
    if doc_type not in valid_types:
        return JsonResponse({'success': False, 'message': 'Invalid document type'}, status=400)
    
    try:
        hr_profile = hr_collection.find_one(
            {"_id": ObjectId(hr_id)},
            {doc_type: 1, f"{doc_type}_content_type": 1}
        )
        
        if not hr_profile or doc_type not in hr_profile:
            return JsonResponse({'success': False, 'message': 'Document not found'}, status=404)
        
        return JsonResponse({
            'success': True,
            'content_type': hr_profile.get(f"{doc_type}_content_type", "application/octet-stream"),
            'data': hr_profile[doc_type]
        })
    
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)
    
@csrf_exempt
def update_subscription(request):
    if not request.session.get('hr_id'):
        return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)
    
    if request.method == 'POST':
        try:
            hr_id = request.session['hr_id']
            hr_data = hr_collection.find_one({"_id": ObjectId(hr_id)})
            if not hr_data:
                return JsonResponse({'success': False, 'message': 'HR not found'}, status=404)

            current_status = hr_data.get('is_active', False)
            new_status = not current_status
            print(f"New status: {new_status}")

            result = hr_collection.update_one(
                {"_id": ObjectId(hr_id)},
                {"$set": {"is_active": new_status}}
            )
        

            if result.matched_count == 1:
                request.session['is_active'] = new_status
                return JsonResponse({
                    'success': True,
                    'message': "Premium activated!" if new_status else "Premium deactivated",
                    'is_active': new_status
                })

            return JsonResponse({'success': False, 'message': 'Update failed'})

        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Error: {str(e)}'}, status=500)

    return JsonResponse({'success': False, 'message': 'Only POST requests allowed'}, status=400)

def hrprofile(request):
    if not request.session.get('hr_id'):
        return redirect('loginhr')
    
    hr_id = request.session['hr_id']
    
    hr_user = hr_collection.find_one({"_id": ObjectId(hr_id)})
    is_active = hr_user.get('is_active') if hr_user else False
    if request.method == 'GET':
        # Fetch HR profile data
        hr_profile = hr_collection.find_one({"_id": ObjectId(hr_id)})
        
        if not hr_profile:
            return JsonResponse({'success': False, 'message': 'HR profile not found'}, status=404)
        
        # Handle is_active properly - convert to Python boolean
        is_active = hr_profile.get('is_active', False)
        if isinstance(is_active, str):
            is_active = is_active.lower() == 'true'
        
        # Prepare context data with proper boolean handling
        context = {
            'hr_profile': {
                'username': hr_profile.get('hrname', ''),
                'email': hr_profile.get('email', ''),
                'mobile': hr_profile.get('mobile', ''),
                'linkedin': hr_profile.get('linkedin', ''),
                'profile_picture': hr_profile.get('profile_picture', ''),
                'company_name': hr_profile.get('company_name', ''),
                'company_email': hr_profile.get('company_email', ''),
                'company_website': hr_profile.get('company_website', ''),
                'company_industry': hr_profile.get('company_industry', ''),
                'company_size': hr_profile.get('company_size', ''),
                'company_description': hr_profile.get('company_description', ''),
                'hr_position': hr_profile.get('position', ''),
                'hr_department': hr_profile.get('department', ''),
                'hr_certification': hr_profile.get('certification', ''),
                'certification_year': hr_profile.get('certification_year', ''),
                'hr_specialization': hr_profile.get('specialization', ''),
                'is_active': bool(is_active),  # Ensure boolean type
                'jobs_posted': job_collection.count_documents({"hr_id": hr_id}),
                'candidates_reviewed': 0,
                'interviews_scheduled': 0,
                  # Ensure boolean type
            },
            'is_active': is_active
        } 
        
        
        return render(request, 'hrprofile.html', context)
    
    return render(request, 'hrprofile.html')