from flask import Flask, Response, make_response, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS
import json
import secrets 
from datetime import datetime, timedelta

app = Flask(__name__)

# Enable CORS for all routes
CORS(app)

# Generate a random session ID
def generate_session_id():
    return secrets.token_hex(32)  # 64 hex characters

# Store session in db.json
def store_session(user_id, session_id):
    data = load_data()
    session_expiry = datetime.utcnow() + timedelta(hours=24)
    new_session = {
        "session_id": session_id,
        "user_id": user_id,
        "expires_at": session_expiry.isoformat()
    }
    data['sessions'].append(new_session)
    with open('db.json', 'w') as f:
        json.dump(data, f)

# clean the session
def clean_expired_sessions():
    data = load_data()
    now = datetime.utcnow()
    data['sessions'] = [s for s in data['sessions'] if datetime.fromisoformat(s['expires_at']) > now]
    with open('db.json', 'w') as f:
        json.dump(data, f)


# Load data from db.json
def load_data():
    with open('db.json') as f:
        return json.load(f)

def save_data(data):
    with open('db.json', 'w') as f:
        json.dump(data, f, indent=4)



# @app.before_request
# def check_session():
#     # List of routes that should be accessible without authentication
#     public_routes = ['static', 'load_welcome_view', 'register', 'login', 'login_submit' 'default_content', 'about']
#     print(f"requested endpoint {request.endpoint}\n")

#     if request.endpoint in public_routes:
#         # Allow access to public routes without session check
#         return

#     session_id = request.cookies.get('session_id')
#     if session_id:
#         data = load_data()
#         session = next((s for s in data['sessions'] if s['session_id'] == session_id), None)
#         if session and datetime.fromisoformat(session['expires_at']) > datetime.utcnow():
#             # Session is valid
#             # Attach user information to the request if needed
#             request.user_id = session['user_id']
#         else:
#             # Session expired or not found
#             return redirect(url_for('load_welcome_view'))  # Redirect to login or other appropriate page
#     else:
#         # No session ID found
#         return redirect(url_for('load_welcome_view'))  # Redirect to login
       
@app.route('/')
def load_welcome_view():
    return render_template('index.html')

@app.route('/register', methods=['GET'])
def register():
    return render_template('register.html')

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.form
    otp = data.get('first_otp')
    
    db = load_data()
    otps = db.get('otps', [])
    
    otp_entry = next((entry for entry in otps if entry['otp'] == otp), None)
    
    if otp_entry and otp_entry['status'] == 'valid':
        # Mark OTP as used
        otp_entry['status'] = 'used'
        with open('db.json', 'w') as f:
            json.dump(db, f, indent=4)
        return render_template('add_password.html')
    else:
        otp_message_error = "You have entered an invalid OTP"
        return render_template('general_error.html', message=otp_message_error)


@app.route('/add-password', methods=['POST'])
def load_add_password():
    # get otp and verify [true or false]
    return render_template('add_password.html')


@app.route('/add-submit', methods=['POST'])
def add_password():
    data = request.form
    email_phone = data.get('email_phone')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    
    if password != confirm_password:
        print(f"passwords do not match")
        pass_error_message = "Your passwords, do not match!"
        return render_template('general_error.html', message=pass_error_message)
        
    
    db = load_data()
    users = db.get('users', [])
    
    # Mock password hashing
    hashed_password = password  # Replace with actual hashing function

    users.append({
        "email_phone": email_phone,
        "password": hashed_password,
        "user_type": "tenant"  # Default user type, or derive from other logic
    })
    
    with open('db.json', 'w') as f:
        json.dump(db, f, indent=4)
    
    success_message = "You have successfully registerd your account!"
    return render_template('general_success.html', message=success_message)


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/login-submit', methods=['POST'])
def login_submit():
    data = request.form
    email_phone = data.get('email_phone')
    password = data.get('password')
    
    db = load_data()
    users = db.get('users', [])
    
    user = next((u for u in users if u['email_phone'] == email_phone and u['password'] == password), None)
    
    if user:
        user_type = user['user_type']
        user_id = user['id']  # Ensure this is set in your user data

        # Generate session ID and store it
        session_id = generate_session_id()
        print(f"generated session id is : {session_id}")
        store_session(user_id, session_id)

        # Set session cookie and redirect based on user type
        resp = make_response()
        resp.set_cookie('session_id', session_id, max_age=86400)  # 24 hours
        
        if user_type == 'landlord':
            return redirect('/landlord')
        elif user_type == 'admin':
            return redirect('/admin')
        elif user_type == 'tenant':
            return redirect('/tenant')
        # Add more user types if needed
    else:
        login_error_message = "You have entered invalid credentials!"
        return render_template('general_error.html', message=login_error_message)

@app.route('/default-content', methods=['GET'])
def default_content():
    return render_template('default.html')

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/tenant')
def tenant_home():
    return render_template('tenant.html')

@app.route('/admin')
def admin_home():
    return render_template('admin.html')

@app.route('/landlord')
def landlord_home():
    return render_template('landlord.html')
if __name__ == '__main__':
    app.run(port=3000, debug=True)
