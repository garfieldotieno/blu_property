from models import User
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash

# Database setup
engine = create_engine('sqlite:///property.db')  # Adjust this to your actual database
Session = sessionmaker(bind=engine)
session = Session()

# Creating the mock admin user
mock_admin = User(
    email_or_phone="admin75@example.com",  # Replace with your desired admin email/phone
    password=generate_password_hash("adminpassword"),  # Replace with your desired admin password
    user_type="admin"
)

# Adding the mock admin to the database
session.add(mock_admin)
session.commit()

print("Mock admin user created.")
