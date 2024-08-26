from flask import Flask, request, jsonify, make_response, redirect, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
import secrets
import json 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS 
from datetime import timedelta, datetime
from models import User  # Assuming your models.py is correctly set up and User model is defined
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)
CORS(app)

# Database setup
engine = create_engine('sqlite:///property.db')
Session = sessionmaker(bind=engine)
db_session = Session()

# Utility function to load user by email_or_phone
def load_user_by_email_or_phone(email_or_phone):
    return db_session.query(User).filter_by(email_or_phone=email_or_phone).first()

# Utility function to store session (for demo purposes)
def store_session(user_id, session_id):
    # Implement session storing logic here
    pass

# Landing page
@app.route('/')
def load_welcome_view():
    return render_template('index.html')

@app.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/default-content', methods=['GET'])
def default_content():
    return render_template('default.html')

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')


# Registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email_or_phone = data.get('email_or_phone')
    password = data.get('password')

    if not email_or_phone or not password:
        return jsonify({"msg": "Email/Phone and Password required"}), 400

    hashed_password = generate_password_hash(password)

    # Save the new user in the database
    new_user = User(email_or_phone=email_or_phone, password=hashed_password, user_type='regular_visitor')
    db_session.add(new_user)
    db_session.commit()

    # Create the JWT tokens
    access_token = create_access_token(identity=new_user.id)
    refresh_token = create_refresh_token(identity=new_user.id)

    # Return the tokens in the response
    return jsonify(access_token=access_token, refresh_token=refresh_token), 201


# Login route
@app.route('/login', methods=['POST'])
def process_login():
    data = request.json
    email_or_phone = data.get('email_or_phone')
    password = data.get('password')

    user = load_user_by_email_or_phone(email_or_phone)

    if not user or not check_password_hash(user.password, password):
        return jsonify({"msg": "Bad email/phone or password"}), 401

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify(access_token=access_token, refresh_token=refresh_token)


# Token refresh route
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token)


# Logout route (for demonstration purposes)
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # Here you would handle the invalidation of the JWT (e.g., blacklist it)
    return jsonify({"msg": "Logout successful"}), 200


# Protected route example
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route('/tenant')
@jwt_required()
def tenant_home():
    return render_template('tenant.html')

@app.route('/admin')
@jwt_required()
def admin_home():
    return render_template('admin.html')

@app.route('/landlord')
@jwt_required()
def landlord_home():
    return render_template('landlord.html')

if __name__ == '__main__':
    app.run(port=3000, debug=True)
