from enum import unique
import json
from flask import Flask, render_template, request, abort, redirect, make_response, url_for, session, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import string, random
from flask_sqlalchemy import SQLAlchemy
import time
from flask_cors import CORS

# from reportlab.lib.pagesizes import landscape, letter
# from reportlab.lib import colors
# from reportlab.lib.styles import getSampleStyleSheet
# from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, PageBreak
from io import BytesIO

app = Flask(__name__)
app.secret_key = b"Z'(\xac\xe1\xb3$\xb1\x8e\xea,\x06b\xb8\x0b\xc0"
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pos_test.db'
db = SQLAlchemy(app)

app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(hours=2)

@app.template_filter()
def numberFormat(value):
    return format(int(value), 'd')

import pydantic
import yaml
import hashlib

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
    session.clear()
    session['session_user'] = b'Anonymous'
    return {"status":True, "middleware":session_middleware['Anonymous']}         

def switch_session_profile(role):
    """Helper function to switch the session profile"""
    session_key_string = randomString(10)
    session['session_key_string'] = bytes(session_key_string, 'utf-8')
    
    if role == "Admin":
        session['session_user'] = bytes(f'Admin:{session_key_string}', 'utf-8')
    elif role == "LandLord":
        session['session_user'] = bytes(f'LandLord:{session_key_string}', 'utf-8')
    elif role == "Tenant":
        session['session_user'] = bytes(f'Tenant:{session_key_string}', 'utf-8')
    else:
        session['session_user'] = b'Anonymous'
    
    session.permanent = True
    return {"status": True, "role": role}



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


@app.route('/logout')
def clear_auth_session():
    reset_session()
    return redirect('/')

@app.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@app.route('/verify-otp', methods=['POST'])
def process_otp():
    pass 

@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')

def verify_user_credentials(email_or_phone, password):
    # Replace with actual user verification logic
    if email_or_phone == "admin@example.com" and password == "adminpass":
        return {"user_name": "Admin", "user_type": "admin", "access_token": "admin_access", "refresh_token": "admin_refresh"}
    elif email_or_phone == "landlord@example.com" and password == "landlordpass":
        return {"user_name": "Landlord", "user_type": "landlord", "access_token": "landlord_access", "refresh_token": "landlord_refresh"}
    elif email_or_phone == "tenant@example.com" and password == "tenantpass":
        return {"user_name": "Tenant", "user_type": "tenant", "access_token": "tenant_access", "refresh_token": "tenant_refresh"}
    else:
        return None

@app.route('/verify-login', methods=['POST'])
def process_login():
    data = request.form
    email_or_phone = data.get("email_or_phone")
    password = data.get("password")
    user_info = verify_user_credentials(email_or_phone, password)

    if user_info:
        if user_info['user_type'] == "admin":
            message = "Proceed to Admin dashboard"
            dashboard_url = "/login-admin"
            return render_template('proceed_login.html', message=message, dashboard_url=dashboard_url)
             
        elif user_info['user_type'] == "landlord":
            message = "Proceed to LandLord dashboard"
            dashboard_url = "/login-landlord"
            return render_template('proceed_login.html', message=message, dashboard_url=dashboard_url)
             
        elif user_info['user_type'] == "tenant":
            message = "Proceed to Tenant dashboard"
            dashboard_url = "/login-tenant"
            return render_template('proceed_login.html', message=message, dashboard_url=dashboard_url)
             
        else:
            # Default response for any other user_type or unexpected value
            message = "Unknown user type"
            return render_template('general_error.html', message=message)
    else:
        message = "Invalid Credentials"
        return render_template('general_error.html', message=message)


@app.route('/default-content', methods=['GET'])
def show_default_content():
    return render_template('default.html')


@app.route('/about', methods=['GET'])
def show_about():
    return render_template('about.html')


# protected
# Unguarded routes
@app.route('/login-admin')
def test_admin_access():
    switch_session_profile("Admin")
    return redirect('/admin')


@app.route('/login-landlord')
def test_landlord_access():
    switch_session_profile("LandLord")
    return redirect('/landlord')


@app.route('/login-tenant')
def test_tenant_access():
    switch_session_profile("Tenant")
    return redirect('/tenant')


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