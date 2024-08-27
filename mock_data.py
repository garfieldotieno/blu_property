from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, Property, Unit, Lease, PaymentReminder, PaymentConfirmation, Receipt
import datetime
from passlib.context import CryptContext

# Configure database URL
DATABASE_URL = "sqlite:///property.db"  # Ensure this matches your DATABASE_URL
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a password context for hashing and verifying passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def init_db():
    Base.metadata.create_all(bind=engine)
    print("All Tables Created!")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def populate_mock_data():
    session = SessionLocal()

    try:
        # Admin User Creation
        admin = User(
            uid="A0001",
            user_name="AdminUser",
            email_or_phone="admin@propertyapp.com",
            password_hash=hash_password("adminpass"),
            user_type="Admin"
        )
        session.add(admin)
        
        # Landlord Users Creation
        landlords = [
            User(uid="L0001", user_name="LandlordOne", email_or_phone="landlord1@example.com", password_hash=hash_password("landlordpass1"), user_type="Landlord"),
            User(uid="L0002", user_name="LandlordTwo", email_or_phone="landlord2@example.com", password_hash=hash_password("landlordpass2"), user_type="Landlord"),
            User(uid="L0003", user_name="LandlordThree", email_or_phone="landlord3@example.com", password_hash=hash_password("landlordpass3"), user_type="Landlord")
        ]
        session.add_all(landlords)
        
        # Tenant Users Creation
        tenants = [
            User(uid="T0001", user_name="TenantOne", email_or_phone="tenant1@example.com", password_hash=hash_password("tenantpass1"), user_type="Tenant"),
            User(uid="T0002", user_name="TenantTwo", email_or_phone="tenant2@example.com", password_hash=hash_password("tenantpass2"), user_type="Tenant"),
            User(uid="T0003", user_name="TenantThree", email_or_phone="tenant3@example.com", password_hash=hash_password("tenantpass3"), user_type="Tenant"),
            User(uid="T0004", user_name="TenantFour", email_or_phone="tenant4@example.com", password_hash=hash_password("tenantpass4"), user_type="Tenant")
        ]
        session.add_all(tenants)
        
        # Properties Creation
        properties = [
            Property(name="Property 1", landlord_id=1),
            Property(name="Property 2", landlord_id=1),
            Property(name="Property 3", landlord_id=2)
        ]
        session.add_all(properties)
        
        # Units Creation
        units = [
            Unit(number="101", property_id=1),
            Unit(number="102", property_id=1),
            Unit(number="201", property_id=2),
            Unit(number="301", property_id=3),
            Unit(number="302", property_id=3)
        ]
        session.add_all(units)
        
        # Leases Creation
        leases = [
            Lease(tenant_id=1, unit_id=1, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
            Lease(tenant_id=2, unit_id=2, start_date=datetime.datetime(2024, 2, 1), end_date=datetime.datetime(2024, 8, 31), rent_amount=600.00),
            Lease(tenant_id=3, unit_id=3, start_date=datetime.datetime(2024, 3, 1), end_date=datetime.datetime(2024, 11, 30), rent_amount=550.00),
            Lease(tenant_id=4, unit_id=4, start_date=datetime.datetime(2024, 4, 1), end_date=datetime.datetime(2024, 10, 31), rent_amount=650.00)
        ]
        session.add_all(leases)
        
        # Payment Reminders Creation
        reminders = [
            PaymentReminder(lease_id=1, reminder_date=datetime.datetime(2024, 12, 1)),
            PaymentReminder(lease_id=2, reminder_date=datetime.datetime(2024, 8, 1)),
            PaymentReminder(lease_id=3, reminder_date=datetime.datetime(2024, 11, 1))
        ]
        session.add_all(reminders)
        
        # Payment Confirmations Creation
        confirmations = [
            PaymentConfirmation(lease_id=1, confirmation_date=datetime.datetime(2024, 1, 2), payment_details="Payment received for January."),
            PaymentConfirmation(lease_id=2, confirmation_date=datetime.datetime(2024, 2, 2), payment_details="Payment received for February."),
            PaymentConfirmation(lease_id=3, confirmation_date=datetime.datetime(2024, 3, 2), payment_details="Payment received for March.")
        ]
        session.add_all(confirmations)
        
        # Receipts Creation
        receipts = [
            Receipt(lease_id=1, receipt_date=datetime.datetime(2024, 1, 3), amount=500.00, receipt_number="R001", description="January rent payment."),
            Receipt(lease_id=2, receipt_date=datetime.datetime(2024, 2, 3), amount=600.00, receipt_number="R002", description="February rent payment."),
            Receipt(lease_id=3, receipt_date=datetime.datetime(2024, 3, 3), amount=550.00, receipt_number="R003", description="March rent payment.")
        ]
        session.add_all(receipts)

        session.commit()
        print("Mock Data Populated!")

    except Exception as e:
        print(f"An error occurred: {e}")
        session.rollback()
    
    finally:
        session.close()

if __name__ == "__main__":
    init_db()
    populate_mock_data()
