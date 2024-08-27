from enum import unique
import json
from flask import Flask, render_template, request, abort, redirect, make_response, url_for, session, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import string, random
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker 
from passlib.context import CryptContext
import jwt 

import time
from flask_cors import CORS

# from reportlab.lib.pagesizes import landscape, letter
# from reportlab.lib import colors
# from reportlab.lib.styles import getSampleStyleSheet
# from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, PageBreak
from io import BytesIO
from models import User, Otp, Session, Property, Unit, Lease, PaymentReminder, PaymentConfirmation, Receipt 
import random 
import pydantic
import yaml
import hashlib
import random 
import os


app = Flask(__name__)
app.secret_key = b"Z'(\xac\xe1\xb3$\xb1\x8e\xea,\x06b\xb8\x0b\xc0"
CORS(app)



DATABASE_URL = "sqlite:///property.db"  # Ensure this matches your DATABASE_URL
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db_session = SessionLocal()


app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(hours=2)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Secret Key for token generation
SECRET_KEY = "your_jwt_secret_key"
ALGORITHM = "HS256"




@app.template_filter()
def numberFormat(value):
    return format(int(value), 'd')


def randomString(stringLength=100):
    """Generate a random string of fixed length """
    letters = string.ascii_uppercase
    return ''.join(random.choice(letters) for i in range(stringLength))

session_middleware = {
    "Anonymous": {"allowed_routes": ['/', '/about', '/invalid', '/register', '/login', '/default-content', '/about']},
    "Admin" : {"allowed_routes":['/admin']},
    "LandLord":{"allowed_routes":['/landlord',]},
    "Tenant" : {"allowed_routes":['/tenant']}
}

def generate_login_session(user_type):
    """Generate a unique and secure login session token based on user type and randomness."""
    # Use a combination of user type, a random value, and a secret key
    random_value = os.urandom(16)  # Generate a 16-byte random value
    data = f"{user_type}:{random_value.hex()}:{SECRET_KEY}".encode()
    session_token = hashlib.sha256(data).hexdigest()
    return session_token

def verify_login_session(input_expected_user_type):
    """Verify the login session stored in the session cookie."""
    session_token = request.cookies.get('login_session')
    print(f"fetched session for login_session cookie is : {session_token}")

    if not session_token:
        return False  # No session token found

    expected_session_token = session.get('session_token')
    print(f"fetched session from session_token is : {expected_session_token}")

    expected_user_type = session.get('user_type')
    print(f"fetched user type is : {expected_user_type}")

    sess_compare_result = session_token == expected_session_token
    print(f"compared sess_compare_result is : {sess_compare_result}")

    print(f"incoming user_type from func call is : {input_expected_user_type}")
    print(f"user_type from session is : {expected_user_type}")

    user_type_compare_result = input_expected_user_type == expected_user_type
    print(f"compared user_type result is : {user_type_compare_result}")

    return sess_compare_result and user_type_compare_result


def is_active():
    print(f"calling is_active and endpoint is {request.endpoint}")
    if 'session_user' in session :
        print("cookie session_user in place")
        print(f"\n")
        print(f"cookie is : {session['session_user']}")
        print("\n")

        return {"status":True, "middleware":session_middleware[session['session_user'].decode('utf-8').split(':')[0]] }
    else:
        reset_session()
        return {"status":False, "middleware":session_middleware['Anonymous'] }

def reset_session():
    # Clear the Flask session
    session.clear()
    session['session_user'] = b'Anonymous'


def switch_session_profile(role):
    print(f"\ncalling the switch profile and input is {role} \n")
    """Helper function to switch the session profile"""
    session_key_string = randomString(10)
    session['session_key_string'] = bytes(session_key_string, 'utf-8')
    
    if role == "Admin":
        print(f"\n now switching session to admin")
        session['session_user'] = bytes(f'Admin:{session_key_string}', 'utf-8')
    elif role == "Landlord":
        print(f"\n now switching session to landlord")
        session['session_user'] = bytes(f'LandLord:{session_key_string}', 'utf-8')
    elif role == "Tenant":
        print(f"\n now switching session to tenant")
        session['session_user'] = bytes(f'Tenant:{session_key_string}', 'utf-8')
    else:
        session['session_user'] = b'Anonymous'
    
    session.permanent = True
    return {"status": True, "role": role}


def verify_user_credentials(email_or_phone: str, password: str):
    """
    Verify user credentials against the database.

    Args:
        email_or_phone (str): The email or phone number of the user.
        password (str): The password provided by the user.

    Returns:
        dict or None: Returns user information and tokens if credentials are valid, otherwise None.
    """
    user = db_session.query(User).filter(User.email_or_phone == email_or_phone).first()
        
    if user and pwd_context.verify(password, user.password_hash):
        # Generate tokens (placeholder logic for token creation)
        access_token = jwt.encode({"sub": user.uid, "exp": datetime.utcnow() + timedelta(hours=1)}, SECRET_KEY, algorithm=ALGORITHM)
        refresh_token = jwt.encode({"sub": user.uid, "exp": datetime.utcnow() + timedelta(days=7)}, SECRET_KEY, algorithm=ALGORITHM)
        print(f"user found {user.user_name}")
        
        return {
            "user_name": user.user_name,
            "user_type": user.user_type,
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    
    else:
        print(f"user not found : {user}")
        return None
    
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


@app.route('/')
def index():
    query = is_active()
    print(f"query return type is, {type(query)}")
    print(f"query return is : {query}")
    if query['status'] and request.path in query['middleware']['allowed_routes']:
        print(request.path)
        response = make_response(render_template(
        'index.html',
        ))  
        return response
    return redirect(query['middleware']['allowed_routes'][0])




@app.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@app.route('/verify-otp', methods=['POST'])
def process_otp():
    pass 

@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')

@app.route('/default-content', methods=['GET'])
def show_default_content():
    return render_template('default.html')


@app.route('/about', methods=['GET'])
def show_about():
    return render_template('about.html')


@app.route('/verify-login', methods=['POST'])
def process_login():
    data = request.form
    email_or_phone = data.get("email_or_phone")
    password = data.get("password")
    user_info = verify_user_credentials(email_or_phone, password)

    if user_info:
        session_token = generate_login_session(user_info['user_type'])
        session['session_token'] = session_token
        session['user_type'] = user_info['user_type']

        # Format the dashboard URL based on user type
        user_type = user_info['user_type'].lower()
        dashboard_url = f"/login-{user_type}"

        resp = make_response(render_template('proceed_login.html', message=f"Proceed to {user_info['user_type']} dashboard", dashboard_url=dashboard_url))
        resp.set_cookie('login_session', session_token, httponly=True)

        return resp
    
    else:
        message = "Invalid Credentials"
        return render_template('general_error.html', message=message)

@app.route('/login-admin')
def test_admin_access():
    if verify_login_session('Admin'):
        switch_session_profile('Admin')
        return redirect('/admin')
    else:
        return "Unauthorized Access", 403


@app.route('/login-landlord')
def test_landlord_access():
    if verify_login_session('Landlord'):
        switch_session_profile('Landlord')
        return redirect('/landlord')
    else:
        return "Unauthorized Access", 403


@app.route('/login-tenant')
def test_tenant_access():
    if verify_login_session('Tenant'):
        switch_session_profile('Tenant')
        return redirect('/tenant')
    else:
        return "Unauthorized Access", 403

@app.route('/logout')
def logout():
    reset_session()
    resp = make_response(redirect(url_for('index')))  # Redirect to the home page or login page
    resp.set_cookie('login_session', '', expires=0)  # Clear the login session cookie
    return resp


@app.route('/tenant')
def tenant_home():
    query = is_active()
    print(f"query return type is, {type(query)}")
    print(f"query return is : {query}")
    if query['status'] and request.path in query['middleware']['allowed_routes']:
        print(request.path)
        response = make_response(render_template(
        'tenant.html',
        ))  
        return response
    return redirect(query['middleware']['allowed_routes'][0])


@app.route('/admin')
def admin_home():
    query = is_active()
    print(f"query return type is, {type(query)}")
    print(f"query return is : {query}")
    if query['status'] and request.path in query['middleware']['allowed_routes']:
        print(request.path)
        response = make_response(render_template(
        'admin.html',
        ))  
        return response
    return redirect(query['middleware']['allowed_routes'][0])



@app.route('/admin-users')
def get_admin_users():
    users = db_session.query(User).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin-add-user')
def admin_add_user():
    return render_template('add_user.html')


def generate_otp_code(length=6):
    """
    Generates a numeric OTP code of specified length.
    
    Parameters:
        length (int): The length of the OTP code to generate. Default is 6.
    
    Returns:
        str: The generated OTP code.
    """
    otp_code = ''.join([str(random.randint(0, 9)) for _ in range(length)])
    return otp_code


@app.route('/add-user', methods=['POST'])
def add_user():
    user_name = request.form.get('user_name')
    email_or_phone = request.form.get('email_or_phone')
    user_type = request.form.get('user_type')
    otp_value = request.form.get('user_otp')

    if not user_name or not email_or_phone or not user_type:
        return render_template('generate_error.html', message="All fields are required.")

    hashed_password = generate_password_hash('default_password')

    try:
        # Create and save new user record
        new_user = User(uid = generate_otp_code(10), user_name=user_name, email_or_phone=email_or_phone, user_type=user_type, password_hash=hashed_password)
        db_session.add(new_user)
        db_session.commit()

        if otp_value == 'yes':
            otp_code = generate_otp_code()
            otp_record = Otp(user_type=user_type, otp=otp_code)
            db_session.add(otp_record)
            db_session.commit()
            message = f"User{new_user.user_name} added and OTP generated. OTP Code: {otp_code}"
        else:
            message = "User added successfully."

        return render_template('general_success.html', message=message)
    
    except Exception as e:
        db_session.rollback()
        message = f"An error occurred: {str(e)}"
        return render_template('general_error.html', message=message)


@app.route('/landlord')
def landlord_home():
    query = is_active()
    print(f"query return type is, {type(query)}")
    print(f"query return is : {query}")
    if query['status'] and request.path in query['middleware']['allowed_routes']:
        print(request.path)
        response = make_response(render_template(
        'landlord.html',
        ))  
        return response
    return redirect(query['middleware']['allowed_routes'][0])



if __name__ == '__main__':
    app.run(port=5000, debug=True)