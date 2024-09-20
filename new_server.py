from enum import unique
import json
from flask import Flask, render_template, request, abort, redirect, make_response, url_for, session, send_file, jsonify
from flask import current_app
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


from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from xhtml2pdf import pisa
from io import BytesIO

from io import BytesIO
from models import User, Otp, Session, Property, Unit, Lease, PaymentReminder, PaymentConfirmation, Receipt, License, LicenseResetKey
import random 
import pydantic
import yaml
import hashlib
from random import choice
import os

import barcode
from barcode.writer import ImageWriter



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


def load_shop_data():
    json_file = open("shop_config.json")
    data = json.load(json_file)
    print('shop config,', data)
    print(type(data))
    return data


@app.template_filter()
def numberFormat(value):
    return format(int(value), 'd')


def randomString(stringLength=100):
    """Generate a random string of fixed length """
    letters = string.ascii_uppercase
    return ''.join(random.choice(letters) for i in range(stringLength))

session_middleware = {
    "Anonymous": {
        "allowed_routes": ['/', '/about', '/invalid', '/register', '/login', '/default-content', '/about', '/verify-otp']
    },
    "Admin": {
        "allowed_routes": ['/admin'] 
    },
    "LandLord": {
        # Dynamically generate routes from /landlord/2 to /landlord/100
        # "allowed_routes": ['/landlord'] + [f'/landlord/{i}' for i in range(2, 101)]
        "allowed_routes": [f'/landlord/{i}' for i in range(2, 101)]
    },
    "Tenant": {
        "allowed_routes": ['/tenant'] + [f'/tenant/{i}' for i in range(2,100)]
    }
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
            "refresh_token": refresh_token,
            "user_id":user.id
        }
    
    else:
        print(f"user not found : {user}")
        return None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_license(payload):
    # update so that there can only be one record
    license = License()
    license.uid = randomString(16)
    license.license_key = payload['license_key']
    license.license_type = payload['license_type']
    license.license_status = payload['license_status']
    license.license_expiry = payload['license_expiry']

    # check length of records, if empty add, if one, delete and create new
    if db_session.query(License).all() == []:
        db_session.add(license)
        db_session.commit()
        return {"status":True}
    else:
        delete_license(1)
        db_session.add(license)
        db_session.commit()
        return {"status":True}


def fetch_licenses():
    return db_session.query(License).all()


def fetch_license(uid):
    return db_session.query(License).filter_by(uid=uid).first()
    

def delete_license(license_id):
    license = db_session.query(License).filter_by(id=license_id).first()
    db_session.delete(license)
    return db_session.commit()


def update_license(payload):
    license = db_session.query(License).filter_by(license_key=payload['license_key']).first()
    for key in payload:
        if key != 'license_key':
            setattr(license, key, payload[key])
    license.updated_at = datetime.now()
    db_session.add(license)
    db_session.commit()
    return license


# reset_license function here takes the 16digit value and checks against hashed equivalent in the .pos_key.yml file
# if the hashed value is found, it is deleted and the license is reset be cr4eating new entry in the database
# if the hashed value is not found, the function returns false
def reset_license(payload):
    license = db_session.query(License).filter_by(license_key=payload['license_key']).first()
    if license is not None:
        db_session.delete(license)
        db_session.commit()
        create_license(payload)
        return {"status":True}
    else:
        return {"status":False}


# add validate license reset key
@app.route("/validate_reset_key", methods=["POST"])
def validate_reset_key():
    print("Validating reset key")
    input_key_value = request.form['reset_key']
    input_license_type = request.form['license_type']

    # use LicenseResetKey class to validate the key
    if LicenseResetKey.is_valid_key(input_key_value):
        # If the key is valid, redirect to /
        print("Valid reset key")
        # check if License table has any reocrd,
        # if yes, delete all records and create new record
        # if no, create new record
        if input_license_type == "Full":
            days = 366
        else:
            days = 183

        l = fetch_licenses()

        if l == []:
            # if input_license_type == "Full", days = 366 else 188
            create_license({"license_key":randomString(16), "license_type":input_license_type, "license_status":True, "license_expiry":datetime.now() + timedelta(days=days)})
        else:
            print(f"during reseting l was {l}")
            delete_license(1)
            create_license({"license_key":randomString(16), "license_type":input_license_type, "license_status":True, "license_expiry":datetime.now() + timedelta(days=days)})

        session['session_flash_message'] = bytes("License reset successful", 'utf-8')

        return redirect("/")
        
    else:
        # If the key is invalid, load the flash message and redirect to /
        print("Invalid reset key")
        session['session_flash_message'] = bytes("Invalid reset key", 'utf-8')
        return redirect("/")



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

@app.route('/show-receipt-otp')
def show_receipt_otp():
    return render_template('receipt-otp.html')

def verify_otp(email_or_phone, otp_code):
    try:
        # Query to fetch the OTP for the provided email/phone and otp_code
        fetch_otp = db_session.query(Otp).filter_by(
            user_email=email_or_phone,
            otp=otp_code
        ).one()

        # Check if the OTP is still valid
        if fetch_otp.is_active_upto > datetime.utcnow():
            return {'status': 'success', 'message': 'OTP verified successfully.', 'otp':fetch_otp}
        else:
            return {'status': 'error', 'message': 'OTP has expired.'}

    except Exception as e:
        return {'status': 'error', 'message': f'Invalid OTP or user details. error being ... {e}'}  


@app.route('/verify-otp', methods=['POST'])
def process_otp():
    data = request.form
    email_or_phone = data.get('email_or_phone')
    otp_code = data.get('otp_code')

    # Verify OTP using the previously defined verify_otp function
    verify_status = verify_otp(email_or_phone, otp_code)

    if verify_status['status'] == "success":
        # Define the payload for successful OTP verification
        payload = {
            'message': 'OTP verified successfully.',
            'message_status':True,
            'status': 'success',
            'payload': verify_status['otp'].to_dict()
        }
    else:
        # Define the payload for failed OTP verification
        payload = {
            'message': 'OTP verification failed.',
            'message_status':False,
            'status': 'error',
            'reason': verify_status.get('message', 'Unknown error'),  # Includes error details
        }

    # Return the payload to the frontend using the 'otp-result.html' template
    return render_template('otp-result.html', otp_result_payload=payload) 

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
        if user_type == "landlord":
            dashboard_url = f"/login-{user_type}/{user_info['user_id']}"
            print(f"generated landlord url is : {dashboard_url}") 
        else:
            dashboard_url = f"/login-{user_type}"

        resp = make_response(render_template('proceed_login.html', message=f"Proceed to {user_info['user_type']} dashboard", dashboard_url=dashboard_url, user_info=user_info))
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


@app.route('/login-landlord/<int:user_id>')
def test_landlord_access(user_id):
    print(f"about to set landlord session with id : {user_id}")
    if verify_login_session('Landlord'):
        switch_session_profile('Landlord')
        return redirect(f'/landlord/{user_id}')
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
    return render_template('admin_users.html', users=users, header_title="Users")

@app.route('/admin-user-properties/<int:user_id>', methods=['GET'])
def get_user_properties(user_id):
    print(f"user properties endpoint : {request.endpoint}, is called")
    properties = db_session.query(Property).filter_by(landlord_id=user_id).all()
    print(f"fetched properties is : {properties}")
    return render_template('admin_properties.html', properties=properties, header_title="Properties", front_user_id=user_id)

@app.route('/admin-property-units/<int:property_id>', methods=['GET'])
def get_property_units(property_id):
    print(f"called property units endpoint")
    current_property = db_session.query(Property).filter_by(id=property_id).first()
    
    back_user_id = current_property.landlord_id
    units = db_session.query(Unit).filter_by(property_id=property_id).all()
    print(f"fetched units for property id : {property_id} is : {units}") 
    return render_template('admin_units.html', units=units, header_title="Units", front_property_id=property_id, back_user_id=back_user_id)

@app.route('/admin-unit-leases/<int:unit_id>', methods=['GET'])
def get_unit_lease(unit_id):
    # Fetch the unit and its related property
    unit = db_session.query(Unit).filter_by(id=unit_id).first()
    back_property_id = unit.property_id

    # Fetch all leases for the unit
    leases = db_session.query(Lease).filter_by(unit_id=unit_id).all()
    leases2 = db_session.query(Lease).filter_by(unit_id=unit_id).all()
    print(f"fetched lease for unit is {leases}")
    for lease in leases2:
        print(f"fetched lease dict is : {lease.to_dict()}")

    # Fetch all users for the tenant dropdown
    users = db_session.query(User).filter_by(user_type="Tenant").all()

    # Pass the leases and users to the template
    return render_template(
        'admin_leases.html', 
        leases=leases, 
        users=users,  # Pass the users for the dropdown
        header_title="Leases", 
        front_unit_id=unit_id, 
        back_property_id=back_property_id
    )


@app.route('/admin-lease-payments/<int:lease_id>/<int:tenant_id>', methods=['GET'])
def get_lease_payments(lease_id, tenant_id):
    lease = db_session.query(Lease).filter_by(id=lease_id).first()
    back_unit_id = lease.unit_id
    payment_reminders = db_session.query(PaymentReminder).filter_by(lease_id=lease_id).all()
    payment_confirmations = db_session.query(PaymentConfirmation).filter_by(lease_id=lease_id).all()
    print(f"fetched reminders for lease : {lease_id} are : {payment_reminders}\n")
    print(f"fetched confirmations for lease : {lease_id} are : {payment_confirmations}\n")
    return render_template('admin_payments.html', reminders=payment_reminders, confirmations=payment_confirmations, header_title="Payments", lease_id=lease_id, tenant_id=tenant_id, lease=lease, back_unit_id=back_unit_id)


@app.route('/admin-add-user')
def admin_add_user():
    return render_template('add_user.html')

@app.route('/admin-add-property/<int:landlord_id>')
def admin_add_property(landlord_id):
    return render_template('add_property.html', landlord_id=landlord_id)

@app.route('/admin-add-unit/<int:property_id>')
def admin_add_unit(property_id):
    return render_template('add_unit.html', property_id=property_id)

@app.route('/admin-add-lease/<int:unit_id>')
def admin_add_lease(unit_id):
    return render_template('add_lease.html', unit_id=unit_id)

@app.route('/admin-add-payment-reminder/<int:lease_id>')
def admin_add_payment_reminder(lease_id):
    users = db_session.query(User).all()
    return render_template('add_payment_reminder.html', lease_id=lease_id, users=users)




@app.route('/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    print(f"called delete user endpoint {request.endpoint}")

    user = db_session.query(User).get(user_id)
    if user:
        db_session.delete(user)
        db_session.commit()
        return jsonify({'success': True, 'message': f'User {user.user_name} successfully deleted.'})
    else:
        return jsonify({'success': False, 'message': 'User not found.'}), 404


@app.route('/delete-property/<int:property_id>', methods=['DELETE'])
def delete_property(property_id):
    print(f"called delete property endpoint {request.endpoint}")

    property = db_session.query(Property).get(property_id)
    print(f"fetched property is : {property.to_dict()}")

    if property:
        db_session.delete(property)
        db_session.commit()
        return jsonify({
            'success':True,
            'message':f'Property {property.name} successfully deleted'
        })
    else:
        return jsonify({
            'success':False,
            'message': 'Property not found'
        })

@app.route('/delete-unit/<int:unit_id>', methods=['DELETE'])
def delete_unit(unit_id):
    print(f"called delete unit endpoint : {request.endpoint}")

    unit = db_session.query(Unit).get(unit_id)
    print(f"fetched unit is : {unit.to_dict()}")

    if unit :
        db_session.delete(unit)
        db_session.commit()

        return jsonify({
            'success':True,
            'message':f"Unit {unit.id} successfully deleted"
        })
    else:
        return jsonify({
            'success':False,
            'message':'Unit not found'
        })

@app.route('/delete-lease/<int:lease_id>', methods=['DELETE'])
def delete_lease(lease_id):
    print(f"called delete for lease endpoint : {request.endpoint}")

    lease = db_session.query(Lease).get(lease_id)
    print(f"fetched lease is : {lease.to_dict()}")

    if lease:
        db_session.delete(lease)
        db_session.commit()

        return jsonify({
            'success':True,
            'message':f"Lease {lease.id} successfully deleted"
        })
    else:
        return jsonify({
            'success':False,
            'message':'Lease not found'
        })

@app.route('/delete-reminder/<int:reminder_id>', methods=['DELETE'])
def delete_reminder(reminder_id):
    print(f"called delete reminder")
    reminder = db_session.query(PaymentReminder).get(reminder_id)
    if reminder:
        db_session.delete(reminder)
        db_session.commit()

        return jsonify({
            'success':True,
            'message':f"Reminder {reminder.id} successfully deleted"
        })
    
    else:
        return jsonify({
            'success':False,
            'message':'Reminder not found'
        })


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
    try:
        # Get JSON data from the request
        data = request.json
        print(f"received data is : {data}")

        user_name = data.get('user_name')
        email_or_phone = data.get('email_or_phone')
        user_type = data.get('user_type')
        otp_value = data.get('user_otp')

        # Check for required fields
        if not user_name or not email_or_phone or not user_type:
            return jsonify({'success': False, 'error': 'All fields are required.'}), 400

        # Generate a random password and hash it
        rando_password = generate_otp_code(8)
        hashed_password = hash_password(rando_password)

        # Create a new User record
        new_user = User(
            uid=generate_otp_code(10),
            user_name=user_name,
            email_or_phone=email_or_phone,
            user_type=user_type,
            password_hash=hashed_password
        )

        # Add the new user to the database session
        
        # db_session.add(new_user)
        

        otp_code = None
        if otp_value == 'yes':
            otp_code = generate_otp_code()
            otp_record = Otp(
                user_email=email_or_phone,
                action_name="User Creation",
                action_url="",
                user_type=user_type,
                otp=otp_code
            )
        
        
        db_session.add(new_user)
        db_session.add(otp_record)
        
        
        # commit all changes
        db_session.commit()

        # Build a success message
        message = f"User {new_user.user_name} added successfully."
        if otp_code:
            message += f" OTP generated: {otp_code}, and password: {rando_password}"

        # Return success response as JSON
        print(f"Success in adding user, message: {message}")
        return jsonify({
            'success': True,
            'message': message,
            'user': {
                'id':new_user.id,
                'user_name': new_user.user_name,
                'email_or_phone': new_user.email_or_phone,
                'user_type': new_user.user_type,
                'otp_code': otp_code,
                'password': rando_password
            }
        }), 200

    except Exception as e:
        # Rollback in case of an error
        print(f"Error: {e}")
        db_session.rollback()

        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/add-property', methods=['POST'])
def add_landlord_property():
    try:
        # Get JSON data from the request
        data = request.json
        print(f"received data is : {data}")

        property_name = data.get('property_name')
        landlord_id = data.get('landlord_id')
        property_description = data.get('property_description')

        if not property_name or not landlord_id:
            return jsonify({'success': False, 'error': 'All fields are required.'}), 400
        
        # check if landlord exists
        landlord = db_session.query(User).filter_by(id=landlord_id).first()
        if landlord == None:
            return jsonify({'success':False, 'error':'Landlord does not exist'}), 400
        
        # create new property
        new_property = Property(
            name=property_name,
            landlord_id=landlord_id,
            description=property_description
        )
        db_session.add(new_property)
        db_session.commit()

        message = f"Property '{new_property.name}' added successfully for Landlord ID {landlord_id}."

        return jsonify({
            'success':True,
            'message':message,
            'property':{
                'id': new_property.id,
                'name': new_property.name,
                'landlord_id':new_property.landlord_id,
                'description':new_property.description
            }

        })
    
    except Exception as e:
        # Rollback in case of an error
        print(f"Error: {e}")
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/add-unit', methods=['POST'])
def add_property_unit():
    # get json data 
    try:
        # Get JSON data from the request
        data = request.json
        print(f"received data is : {data}")

        property_id = data.get('property_id')
        unit_house_number = data.get('unit_house_number')
        unit_room_quantity = data.get('unit_room_quantity')
        unit_house_description = data.get('unit_house_description')
        unit_type = data.get('unit_type')

        # Validate input
        if not property_id or not unit_house_number:
            return jsonify({'success': False, 'error': 'All fields are required.'})
        
        
        # Create a new Unit instance 
        new_unit = Unit(
            property_id=property_id,
            number=unit_house_number,
            room_quantity=unit_room_quantity,
            unit_type=unit_type,
            unit_description=unit_house_description,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
            )

            # Add the new unit to the database session and commit
        db_session.add(new_unit)
        db_session.commit()

            
        # Success message
        return jsonify({
            'success':True,
            'message': f"Unit {unit_house_number} added successfully to Property ID {property_id}.",
            'unit' : new_unit.to_dict()
        })
         
    except Exception as e:
        # Rollback in case of an error
        print(f"Error: {e}")
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/add-lease', methods=['POST'])
def add_lease():
    try:
        # Get JSON data from the request
        data = request.json
        print(f"Received data is: {data}")

        tenant_id = data.get('tenant_id')
        unit_id = data.get('unit_id')
        room_number = data.get('room_number')
        rent_amount = data.get('rent_amount')
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')

        # Validate input
        if not tenant_id or not unit_id or not start_date_str or not end_date_str:
            return jsonify({'success': False, 'error': 'All fields are required.'})

        # Convert the date strings to datetime objects
        start_date = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')

        # Create a new Lease instance
        new_lease = Lease(
            tenant_id=tenant_id,
            unit_id=unit_id,
            room_number=room_number,
            rent_amount=rent_amount,
            start_date=start_date,
            end_date=end_date,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        # Add the new lease to the database session and commit
        db_session.add(new_lease)
        db_session.commit()

        # Success message
        return jsonify({
            'success': True,
            'message': f"Lease added successfully for Unit ID {unit_id}.",
            'lease': new_lease.to_dict()
        })

    except Exception as e:
        # Rollback the session in case of an error
        print(f"Error: {e}")
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/add-reminder', methods=['POST'])
def add_reminder():
    try:
        # Get JSON data from the request
        data = request.json
        print(f"Received data is: {data}")

        lease_id = data.get('lease_id')
        tenant_id = data.get('tenant_id')
        amount_due = data.get('amount_due')
        due_date_str = data.get('due_date')
        payment_status = data.get('payment_status')

        # Validate input
        if not lease_id or not tenant_id or not amount_due or not due_date_str:
            return jsonify({'success': False, 'error': 'All fields are required.'})

        # Convert the due_date string to datetime object
        due_date = datetime.strptime(due_date_str, '%Y-%m-%dT%H:%M')

        # Create a new PaymentReminder instance
        new_reminder = PaymentReminder(
            lease_id=lease_id,
            tenant_id=tenant_id,
            amount_due=amount_due,
            due_date=due_date,
            payment_status=int(payment_status),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        # Add the new reminder to the database session and commit
        db_session.add(new_reminder)
        db_session.commit()



        # Success message

        success_message =  {
            'success': True,
            'message': f"Payment reminder for Lease ID {lease_id} added successfully.",
            'reminder': new_reminder.to_dict()  # Assuming your model has a to_dict() method
        }

        print(f"created reminder message is : {success_message}")

        return jsonify(success_message)

    except Exception as e:
        # Rollback the session in case of an error
        print(f"Error: {e}")
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/update-reminder/<int:reminder_id>', methods=['POST'])
def update_reminder(reminder_id):
    # Get JSON data from the request
    data = request.get_json()

    try:
        # Fetch the PaymentReminder by the given reminder_id
        reminder = db_session.query(PaymentReminder).get(reminder_id)
        print(f"reminder id is : {reminder.id}")
        
        if not reminder:
            return jsonify({'success': False, 'error': 'Payment reminder not found'}), 404

        # Update the payment confirmation status and any other necessary fields
        # reminder.payment_confirmation_issued = data.get('confirmation_status', False)
        reminder.payment_confirmation_issued = data.get('confirmation_status')
        reminder.updated_at = datetime.utcnow()

        # Create a new PaymentConfirmation record
        new_payment_confirmation = PaymentConfirmation(
            lease_id=data.get('lease_id'),
            payment_reminder_id=reminder.id,
            amount_paid=data.get('amount_paid'),
            payment_type=data.get('payment_type'),
            payment_refference=data.get('payment_refference'),  # Typo from frontend should be corrected if necessary
            Payment_description=data.get('payment_description')
        )

        # Add the new confirmation and update the reminder in the session
        db_session.add(new_payment_confirmation)
        db_session.commit()

        # Return the response containing the new PaymentConfirmation details
        return jsonify({
            'success': True,
            'message': f"Payment reminder for ID {reminder_id} has been updated and payment confirmation added successfully.",
            'payment_confirmation': new_payment_confirmation.to_dict()
        }), 200

    except Exception as e:
        # Rollback the session if there is an error and return the error message
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    


@app.route('/clear-confirmation/<int:confirmation_id>', methods=['POST'])
def clear_confirmation(confirmation_id):
    print(f"recieved confirmation id is : {confirmation_id}")
    try:
        # Get the payment confirmation from the database
        confirmation = db_session.query(PaymentConfirmation).filter_by(id=confirmation_id).first()
        if not confirmation:
            return jsonify({'success': False, 'error': 'Confirmation not found'}), 404

        # Find the associated PaymentReminder
        reminder = db_session.query(PaymentReminder).filter_by(lease_id=confirmation.lease_id).first()

        if reminder:
            print(f"reminder found, and current payment_status is  : {reminder.payment_status}")
            # update the payment_reminder.payment_status if the reminder exists
            reminder.payment_status = True
        else:

            return jsonify({'success': False, 'error': 'Payment reminder not found for lease'}), 404

        # Update the payment_cleared status to True for the confirmation
        confirmation.payment_cleared = True

        # Commit the transaction
        db_session.add_all([reminder,confirmation])
        db_session.commit()

        return jsonify({'success': True, 'confirmation_id': confirmation_id}), 200

    except Exception as e:
        db_session.rollback()
        # Log the error for debugging
        print(f"Error in clearing confirmation: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/download-receipt/<int:confirmation_id>')
def download_receipt(confirmation_id):
    # Fetch the confirmation record
    confirmation = db_session.get(PaymentConfirmation, confirmation_id)
    if not confirmation:
        return jsonify({'error': 'Payment confirmation not found'}), 404

    # Fetch the receipt or generate a new one
    existing_receipt = db_session.query(Receipt).filter_by(confirmation_id=confirmation_id).first()
    existing_lease = db_session.query(Lease).filter_by(id=confirmation.lease_id).first()
    existing_user = db_session.query(User).filter_by(id=existing_lease.tenant_id).first()

    def generate_alpha_numeric(length=6):
        """Generates a random alpha-numerical string."""
        characters = string.ascii_uppercase + string.digits
        return ''.join(choice(characters) for _ in range(length))

    if not existing_receipt:
        # Create a new receipt if one doesn't exist
        receipt_number = f"REC-{generate_alpha_numeric(4)}-{confirmation.id}"

        new_receipt = Receipt(
            receipt_number=receipt_number,
            confirmation_id=confirmation_id,
            lease_id=confirmation.lease_id,
            amount=confirmation.amount_paid,
            description=confirmation.Payment_description,
            receipt_date=confirmation.created_at  # or use current datetime
        )

        otp_code = generate_otp_code()  # Assuming this function is defined elsewhere

        otp_record = Otp(
            user_email=existing_user.email_or_phone,
            action_name='PDF Generation',
            action_url=f'/download-receipt/{confirmation_id}',
            is_active_upto=datetime.utcnow() + timedelta(days=30),
            user_type="tenant",
            otp=otp_code
        )

        # Save new receipt and OTP to the database
        db_session.add(new_receipt)
        db_session.add(otp_record)
        db_session.commit()
    else:
        # Use the existing receipt
        otp_record = db_session.query(Otp).filter_by(user_email=existing_user.email_or_phone).first()
        new_receipt = existing_receipt

    # Barcode generation
    random_number = generate_otp_code() + generate_otp_code()
    
    # Ensure the barcode directory exists
    barcode_dir = os.path.join(current_app.root_path, 'static/barcodes/')
    if not os.path.exists(barcode_dir):
        os.makedirs(barcode_dir)

    # Generate the barcode file path
    barcode_filename = f'{random_number}.png'
    barcode_path = os.path.join(barcode_dir, barcode_filename)
    
    # Generate and save the barcode
    ean = barcode.get('ean13', random_number, writer=ImageWriter())
    ean.save(barcode_path)

    # Generate full filesystem path to the barcode for PDF generation
    barcode_abs_path = os.path.join(current_app.root_path, 'static', 'barcodes', barcode_filename)

    # Render the receipt template with the required data
    rendered_html = render_template(
        'receipt_template.html',
        confirmation=confirmation,
        receipt=new_receipt,
        otp_info=otp_record,
        existing_user=existing_user,
        barcode_path=barcode_abs_path  # Pass the absolute path to the template
    )

    # Convert HTML to PDF
    buffer = BytesIO()
    pisa_status = pisa.CreatePDF(BytesIO(rendered_html.encode('utf-8')), dest=buffer)

    if pisa_status.err:
        return jsonify({'error': 'Error generating PDF'}), 500

    # Move the buffer's position to the start
    buffer.seek(0)

    # Return the generated PDF
    return send_file(buffer, as_attachment=True, download_name=f"Receipt_{new_receipt.receipt_number}.pdf", mimetype='application/pdf')


@app.route('/test-next-pdf')
def show_pdf_page():
    pass 


@app.route('/admin-all-payment-reminders')
def get_all_reminders():
    reminders = db_session.query(PaymentReminder).all()
    return render_template('admin_reminders.html', reminders=reminders, header_title="Payment Reminders")
     
@app.route('/admin-all-payment-confirmations')
def get_all_confirmations():
    confirmations = db_session.query(PaymentConfirmation).all()
    return render_template('admin_confirmations.html', confirmations=confirmations, header_title="Payment Confirmations") 


@app.route('/generate-reminders-report', methods=['POST'])
def all_reminders_report_pdf():
    try:
        print("PDF generation request received")
        # Query all payment reminders from the database
        reminders = db_session.query(PaymentReminder).all()

        # Render the reminders in an HTML template
        rendered_html = render_template('reminders_report_template.html', reminders=reminders, report_date=datetime.now())  # Fix this line

        # Convert the rendered HTML to a PDF
        pdf = BytesIO()  # Create an in-memory buffer
        pisa_status = pisa.CreatePDF(BytesIO(rendered_html.encode('utf-8')), dest=pdf)

        # Check for any errors in PDF generation
        if pisa_status.err:
            print(f"Error in PDF generation: {pisa_status.err}")
            return jsonify({'error': 'Error generating PDF'}), 500

        # Move the buffer's position to the start
        pdf.seek(0)

        # Return the generated PDF as a downloadable response
        generated_name = f"Reminders_Report{randomString(10)}.pdf"
        print(f"generated name is : {generated_name}")
        return send_file(pdf, as_attachment=True, download_name=generated_name, mimetype='application/pdf')

    except Exception as e:
        print(f"Error generating reminders report: {e}")
        return jsonify({'error': str(e)}), 500



@app.route('/generate-confirmations-report', methods=['POST'])
def all_confirmations_report_pdf():
    try:
        print("PDF generation request for confirmations received")

        # Query all payment confirmations from the database
        confirmations = db_session.query(PaymentConfirmation).all()

        # lease_id:tenant_info dict
        lease_tenant_info = {}
        for confirmation in confirmations:
            lease = db_session.query(Lease).filter_by(id=confirmation.lease_id).first()
            user = db_session.query(User).filter_by(id=lease.tenant_id).first()
            print(f"fetched user is : {user}")
            lease_tenant_info[confirmation.lease_id] = user.email_or_phone

        print(f"generated info dict is : {lease_tenant_info}")

        # Render the confirmations in an HTML template
        rendered_html = render_template('confirmations_report_template.html', confirmations=confirmations, report_date=datetime.now(), lease_tenant_info=lease_tenant_info)

        # Convert the rendered HTML to a PDF
        pdf = BytesIO()  # Create an in-memory buffer
        pisa_status = pisa.CreatePDF(BytesIO(rendered_html.encode('utf-8')), dest=pdf)

        # Check for any errors in PDF generation
        if pisa_status.err:
            print(f"Error in PDF generation: {pisa_status.err}")
            return jsonify({'error': 'Error generating PDF'}), 500

        # Move the buffer's position to the start
        pdf.seek(0)

        # Return the generated PDF as a downloadable response
        generated_name = f"Confirmations_Report:{randomString(10)}.pdf"
        print(f"generated name is : {generated_name}")

        return send_file(pdf, as_attachment=True, download_name=generated_name, mimetype='application/pdf')

    except Exception as e:
        print(f"Error generating confirmations report: {e}")
        return jsonify({'error': str(e)}), 500



@app.route('/landlord/<int:user_id>')
def landlord_home(user_id):
    query = is_active()
    print(f"query return type is, {type(query)}")
    print(f"query return is : {query}")
    if query['status'] and request.path in query['middleware']['allowed_routes']:
        print(request.path)
        landlord = db_session.query(User).filter_by(id=user_id).first()
        print(f"at login, fetched landlord with id : {landlord.id}, and email_or_phone value : {landlord.email_or_phone}")
        response = make_response(render_template(
        'landlord.html',
        landlord=landlord
        ))  
        return response
    return redirect(query['middleware']['allowed_routes'][0])


@app.route('/landlord-tenants/<int:user_id>') 
def landlord_tenants(user_id):
    print(f"landlord properties endpoint : {request.endpoint}, is called")
    users = db_session.query(User).all()
    return render_template('landlord_users.html', users=users, header_title="Users", user_id=user_id)

@app.route('/landlord-properties/<int:user_id>')
def landlord_properties(user_id):
    print(f"landlord properties endpoint : {request.endpoint}, is called")
    properties = db_session.query(Property).filter_by(landlord_id=user_id).all()
    print(f"fetched properties is : {properties}")
    return render_template('landlord_properties.html', properties=properties, header_title="Properties", front_user_id=user_id)
     

@app.route('/landlord-property-units/<int:property_id>')
def landlord_property_units(property_id):
    current_property = db_session.query(Property).filter_by(id=property_id).first()
    
    back_user_id = current_property.landlord_id
    units = db_session.query(Unit).filter_by(property_id=property_id).all()
    print(f"fetched units for property id : {property_id} is : {units}") 
    return render_template('landlord_units.html', units=units, header_title="Units", front_property_id=property_id, back_user_id=back_user_id)
     

@app.route('/landlord-unit-leases/<int:unit_id>')
def landlord_unit_leases(unit_id):
    # Fetch the unit and its related property
    unit = db_session.query(Unit).filter_by(id=unit_id).first()
    back_property_id = unit.property_id

    # Fetch all leases for the unit
    leases = db_session.query(Lease).filter_by(unit_id=unit_id).all()
    leases2 = db_session.query(Lease).filter_by(unit_id=unit_id).all()
    print(f"fetched lease for unit is {leases}")
    for lease in leases2:
        print(f"fetched lease dict is : {lease.to_dict()}")

    # Fetch all users for the tenant dropdown
    users = db_session.query(User).filter_by(user_type="Tenant").all()

    # Pass the leases and users to the template
    return render_template(
        'landlord_leases.html', 
        leases=leases, 
        users=users,  # Pass the users for the dropdown
        header_title="Leases", 
        front_unit_id=unit_id, 
        back_property_id=back_property_id
    )

@app.route('/landlord-lease-payments/<int:lease_id>/<int:tenant_id>')
def landlord_lease_payments(lease_id,tenant_id):
    lease = db_session.query(Lease).filter_by(id=lease_id).first()
    back_unit_id = lease.unit_id

    # Fetch all users for the tenant dropdown
    users = db_session.query(User).filter_by(user_type="Tenant").all()

    payment_reminders = db_session.query(PaymentReminder).filter_by(lease_id=lease_id).all()
    payment_confirmations = db_session.query(PaymentConfirmation).filter_by(lease_id=lease_id).all()
    print(f"fetched reminders for lease : {lease_id} are : {payment_reminders}\n")
    print(f"fetched confirmations for lease : {lease_id} are : {payment_confirmations}\n")
    return render_template('landlord_payments.html', reminders=payment_reminders, confirmations=payment_confirmations, header_title="Payments", lease_id=lease_id, tenant_id=tenant_id, back_unit_id=back_unit_id, users=users)
 

@app.route('/landlord-payment-reminders/<int:user_id>')
def get_all_landlord_reminders(user_id):
    reminders = db_session.query(PaymentReminder).all()
    return render_template('landlord_reminders.html', reminders=reminders, header_title="Payment Reminders", user_id=user_id)
    

@app.route('/landlord-payment-confirmations/<int:user_id>')
def get_all_landlord_confirmations(user_id):
    confirmations = db_session.query(PaymentConfirmation).all()
    return render_template('landlord_confirmations.html', confirmations=confirmations, header_title="Payment Confirmations", user_id=user_id) 


if __name__ == '__main__':
    app.run(port=5000, debug=True)