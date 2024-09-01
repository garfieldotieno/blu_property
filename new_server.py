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


from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from xhtml2pdf import pisa
from io import BytesIO

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
    return render_template('admin_users.html', users=users, header_title="Users")

@app.route('/admin-user-properties/<int:user_id>', methods=['GET'])
def get_user_properties(user_id):
    print(f"user properties endpoint : {request.endpoint}, is called")
    properties = db_session.query(Property).filter_by(landlord_id=user_id).all()
    print(f"fetched properties is : {properties}")
    return render_template('admin_properties.html', properties=properties, header_title="Properties", front_user_id=user_id)

@app.route('/admin-property-units/<int:property_id>', methods=['GET'])
def get_property_units(property_id):
    current_property = db_session.query(Property).filter_by(id=property_id).first()
    
    back_user_id = current_property.landlord_id
    units = db_session.query(Unit).filter_by(property_id=property_id).all()
    print(f"fetched units for property id : {property_id} is : {units}") 
    return render_template('admin_units.html', units=units, header_title="Units", front_property_id=property_id, back_user_id=back_user_id)

@app.route('/admin-unit-leases/<int:unit_id>', methods=['GET'])
def get_unit_lease(unit_id):
    unit = db_session.query(Unit).filter_by(id=unit_id).first()
    back_property_id = unit.property_id

    leases = db_session.query(Lease).filter_by(unit_id=unit_id).all()
    leases2 = db_session.query(Lease).filter_by(unit_id=unit_id).all()
    print(f"fetched lease for unit is {leases}")
    for lease in leases2:
        print(f"fetched lease dict is : {lease.to_dict()}")
    return render_template('admin_leases.html', leases=leases, header_title="Leases", front_unit_id=unit_id, back_property_id=back_property_id)

@app.route('/admin-lease-payments/<int:lease_id>/<int:tenant_id>', methods=['GET'])
def get_lease_payments(lease_id, tenant_id):
    lease = db_session.query(Lease).filter_by(id=lease_id).first()
    back_unit_id = lease.unit_id
    payment_reminders = db_session.query(PaymentReminder).filter_by(lease_id=lease_id).all()
    payment_confirmations = db_session.query(PaymentConfirmation).filter_by(lease_id=lease_id).all()
    print(f"fetched reminders for lease : {lease_id} are : {payment_reminders}\n")
    print(f"fetched confirmations for lease : {lease_id} are : {payment_confirmations}\n")
    return render_template('admin_payments.html', reminders=payment_reminders, confirmations=payment_confirmations, header_title="Payments", lease_id=lease_id, tenant_id=tenant_id, back_unit_id=back_unit_id)

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
    return render_template('add_payment_reminder.html', lease_id=lease_id)




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
    user_name = request.form.get('user_name')
    email_or_phone = request.form.get('email_or_phone')
    user_type = request.form.get('user_type')
    otp_value = request.form.get('user_otp')

    if not user_name or not email_or_phone or not user_type:
        response = make_response(render_template('admin.html', pop_message=True, message="All fields are required."))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', "All fields are required.", expires=datetime.now() + timedelta(minutes=5))
        return response

    rando_password = generate_otp_code(8)
    hashed_password = hash_password(rando_password)

    try:
        new_user = User(
            uid=generate_otp_code(10),
            user_name=user_name,
            email_or_phone=email_or_phone,
            user_type=user_type,
            password_hash=hashed_password
        )
        db_session.add(new_user)
        db_session.commit()

        otp_code = None
        if otp_value == 'yes':
            otp_code = generate_otp_code()
            otp_record = Otp(
                user_email=email_or_phone,
                user_type=user_type,
                otp=otp_code
            )
            db_session.add(otp_record)
            db_session.commit()

        message = f"User {new_user.user_name} added successfully."
        if otp_code:
            message += f" OTP generated: {otp_code}, and password : {rando_password}"

        response = make_response(redirect(url_for('admin_home')))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', message, expires=datetime.now() + timedelta(minutes=5))
        return response

    except Exception as e:
        db_session.rollback()
        response = make_response(redirect(url_for('admin_home')))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', f"An error occurred: {str(e)}", expires=datetime.now() + timedelta(minutes=5))
        return response


@app.route('/add-property', methods=['POST'])
def add_landlord_property():
    property_name = request.form.get('property_name')
    landlord_id = request.form.get('landlord_id')
    property_description = request.form.get('property_description')

    if not property_name or not landlord_id:
        response = make_response(render_template('admin.html', pop_message=True, message="Property name and Landlord ID are required."))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', "Property name and Landlord ID are required.", expires=datetime.now() + timedelta(minutes=5))
        return response

    try:
        # Check if the landlord exists
        landlord = db_session.query(User).filter_by(id=landlord_id).first()
        if not landlord:
            response = make_response(render_template('admin.html', pop_message=True, message="Landlord not found."))
            response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
            response.set_cookie('message', "Landlord not found.", expires=datetime.now() + timedelta(minutes=5))
            return response

        # Create a new Property
        new_property = Property(
            name=property_name,
            landlord_id=landlord_id,
            description=property_description
        )
        db_session.add(new_property)
        db_session.commit()

        message = f"Property '{new_property.name}' added successfully for Landlord ID {landlord_id}."
        response = make_response(redirect(url_for('admin_home')))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', message, expires=datetime.now() + timedelta(minutes=5))
        return response

    except Exception as e:
        db_session.rollback()
        response = make_response(redirect(url_for('admin_home')))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', f"An error occurred: {str(e)}", expires=datetime.now() + timedelta(minutes=5))
        return response


@app.route('/add-unit', methods=['POST'])
def add_property_unit():
    # Retrieve form data
    property_id = request.form.get('property_id')
    unit_house_number = request.form.get('unit_house_number')
    unit_room_quantity = request.form.get('unit_room_quantity')
    unit_house_description = request.form.get('unit_house_description')
    unit_type = request.form.get('unit_type')

    # Validate input
    if not property_id or not unit_house_number:
        response = make_response(render_template('admin.html', pop_message=True, message="Property ID and Unit Number are required."))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', "Property ID and Unit Number are required.", expires=datetime.now() + timedelta(minutes=5))
        return response

    try:
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
        message = f"Unit {unit_house_number} added successfully to Property ID {property_id}."
        response = make_response(redirect(url_for('admin_home')))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', message, expires=datetime.now() + timedelta(minutes=5))
        return response

    except Exception as e:
        # Rollback the session in case of an error
        db_session.rollback()
        response = make_response(redirect(url_for('admin_home')))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', f"An error occurred: {str(e)}", expires=datetime.now() + timedelta(minutes=5))
        return response

@app.route('/add-lease', methods=['POST'])
def add_lease():
    try:
        # Retrieve form data
        tenant_id = request.form.get('tenant_id')
        unit_id = request.form.get('unit_id')
        room_number = request.form.get('room_number')
        rent_amount = request.form.get('rent_amount')

        # Parse the date strings into datetime objects
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        
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
        message = f"Lease added successfully for Unit ID {unit_id}."
        response = make_response(redirect(url_for('admin_home')))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', message, expires=datetime.now() + timedelta(minutes=5))
        return response

    except Exception as e:
        # Rollback the session in case of an error
        db_session.rollback()
        response = make_response(redirect(url_for('admin_home')))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', f"An error occurred: {str(e)}", expires=datetime.now() + timedelta(minutes=5))
        return response


@app.route('/add-reminder', methods=['POST'])
def add_reminder():
    # Retrieve form data
    lease_id = request.form.get('lease_id')
    tenant_id = request.form.get('tenant_id')
    amount_due = request.form.get('amount_due')
    due_date = request.form.get('due_date')
    payment_status = request.form.get('payment_status')
    print("\n")
    print(f"{lease_id}")
    print(f"{tenant_id}")
    print(f"{amount_due}")
    print(f"{due_date}")
    print(f"{payment_status}")

    # Validate input
    if not lease_id or not tenant_id or not amount_due or not due_date:
        response = make_response(render_template('admin.html', pop_message=True, message="All fields are required."))
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', "All fields are required.", expires=datetime.now() + timedelta(minutes=5))
        return response

    try:
        # Convert due_date to a Python datetime object
        due_date = datetime.strptime(due_date, '%Y-%m-%dT%H:%M')

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
        message = f"Payment reminder for Lease ID {lease_id} added successfully."
        response = make_response(redirect(url_for('admin_home')))  # Adjust redirection as needed
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', message, expires=datetime.now() + timedelta(minutes=5))
        return response

    except Exception as e:
        # Rollback the session in case of an error
        db_session.rollback()
        response = make_response(redirect(url_for('admin_home')))  # Adjust redirection as needed
        response.set_cookie('pop_message', 'true', expires=datetime.now() + timedelta(minutes=5))
        response.set_cookie('message', f"An error occurred: {str(e)}", expires=datetime.now() + timedelta(minutes=5))
        return response 


@app.route('/update-reminder/<int:reminder_id>', methods=['POST'])
def update_reminder_to_confirmation(reminder_id):
    try:
        # Get the current reminder from the database
        reminder = db_session.query(PaymentReminder).get(reminder_id)
        if not reminder:
            return jsonify({'success': False, 'error': 'Reminder not found'}), 404

        # Update the reminder's payment_confirmation_status to true
        reminder.payment_confirmation_issued = 1

        # Get the form data from the request body
        data = request.get_json()
        lease_id = data.get('lease_id')
        amount_paid = data.get('amount_paid')
        payment_type = data.get('payment_type')
        payment_refference = data.get('payment_refference')
        payment_description = data.get('payment_description')

        # Create a new PaymentConfirmation record
        new_confirmation = PaymentConfirmation(
            lease_id=lease_id,
            payment_reminder_id=reminder_id,
            amount_paid=amount_paid,
            payment_type=payment_type,
            payment_refference=payment_refference,
            Payment_description=payment_description
        )

        # Add the new record to the database session
        db_session.add(new_confirmation)

        # Commit the transaction to the database
        db_session.commit()

        # Return the newly created payment confirmation record as JSON
        return jsonify({
            'success': True,
            'new_confirmation_id': new_confirmation.id,
            'reminder_id': reminder_id,
            'payment_confirmation': {
                'id': new_confirmation.id,
                'lease_id': new_confirmation.lease_id,
                'amount_paid': new_confirmation.amount_paid,
                'payment_type': new_confirmation.payment_type,
                'payment_refference': new_confirmation.payment_refference,
                'payment_description': new_confirmation.Payment_description,
                'created_at': new_confirmation.created_at  # Assuming you have a created_at field
            }
        }), 200

    except Exception as e:
        # Rollback in case of an error
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/clear-confirmation/<int:confirmation_id>', methods=['POST'])
def clear_confirmation(confirmation_id):
    try:
        # Get the payment confirmation from the database
        confirmation = db_session.query(PaymentConfirmation).get(confirmation_id)
        if not confirmation:
            return jsonify({'success': False, 'error': 'Confirmation not found'}), 404

        # update the payment_reminder.payment_status
        reminder = db_session.query(PaymentReminder).filter_by(lease_id=confirmation.lease_id).first()
        reminder.payment_status = True 

        # Update the payment_cleared status to True
        confirmation.payment_cleared = True
        db_session.commit()

        return jsonify({'success': True, 'confirmation_id': confirmation_id}), 200

    except Exception as e:
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500




@app.route('/download-receipt/<int:confirmation_id>')
def download_receipt(confirmation_id):
    # Fetch the confirmation record
    confirmation = db_session.query(PaymentConfirmation).get(confirmation_id)
    if not confirmation:
        return jsonify({'error': 'Payment confirmation not found'}), 404

    # Render HTML template with confirmation data
    rendered_html = render_template('receipt_template.html', confirmation=confirmation)

    # Convert HTML to PDF
    buffer = BytesIO()
    pisa_status = pisa.CreatePDF(BytesIO(rendered_html.encode('utf-8')), dest=buffer)

    if pisa_status.err:
        return jsonify({'error': 'Error generating PDF'}), 500

    # Move the buffer's position to the start
    buffer.seek(0)

    # Return the generated PDF as a response
    return send_file(buffer, as_attachment=True, download_name=f"Receipt_{confirmation_id}.pdf", mimetype='application/pdf')


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