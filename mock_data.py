from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, Otp, Session, Property, Unit, Lease, PaymentReminder, PaymentConfirmation, Receipt
import datetime

DATABASE_URL = "sqlite:///property.db"  # Ensure this matches your DATABASE_URL
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    print("All Tables Created!")

def populate_mock_data():
    session = SessionLocal()

    # Admin User Creation
    admin = User(
        email_or_phone="admin@propertyapp.com",
        password="password",
        user_type="admin"
    )
    session.add(admin)
    
    # Landlord Users Creation
    landlords = [
        User(email_or_phone="landlord1@example.com", password="hashed_password_1", user_type="landlord"),
        User(email_or_phone="landlord2@example.com", password="hashed_password_2", user_type="landlord"),
        User(email_or_phone="landlord3@example.com", password="hashed_password_3", user_type="landlord")
    ]
    session.add_all(landlords)
    
    # Tenant Users Creation
    tenants = [
        User(email_or_phone="tenant1@example.com", password="hashed_password_4", user_type="tenant"),
        User(email_or_phone="tenant2@example.com", password="hashed_password_5", user_type="tenant"),
        User(email_or_phone="tenant3@example.com", password="hashed_password_6", user_type="tenant"),
        User(email_or_phone="tenant4@example.com", password="hashed_password_7", user_type="tenant")
    ]
    session.add_all(tenants)
    
    # OTP Creation
    otps = [
        Otp(otp="123456", user_type="tenant"),
        Otp(otp="654321", user_type="landlord")
    ]
    session.add_all(otps)
    
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
        Lease(tenant_id=1, unit_id=1, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500),
        Lease(tenant_id=2, unit_id=2, start_date=datetime.datetime(2024, 2, 1), end_date=datetime.datetime(2024, 8, 31), rent_amount=600),
        Lease(tenant_id=3, unit_id=3, start_date=datetime.datetime(2024, 3, 1), end_date=datetime.datetime(2024, 11, 30), rent_amount=550),
        Lease(tenant_id=4, unit_id=4, start_date=datetime.datetime(2024, 4, 1), end_date=datetime.datetime(2025, 3, 31), rent_amount=700)
    ]
    session.add_all(leases)
    
    # Payment Reminders Creation
    reminders = [
        PaymentReminder(lease_id=1, reminder_date=datetime.datetime(2024, 7, 1)),
        PaymentReminder(lease_id=2, reminder_date=datetime.datetime(2024, 7, 1)),
        PaymentReminder(lease_id=3, reminder_date=datetime.datetime(2024, 7, 1))
    ]
    session.add_all(reminders)
    
    # Payment Confirmations Creation
    confirmations = [
        PaymentConfirmation(lease_id=1, confirmation_date=datetime.datetime(2024, 7, 5), payment_details="Payment completed"),
        PaymentConfirmation(lease_id=2, confirmation_date=datetime.datetime(2024, 7, 6), payment_details="Payment completed")
    ]
    session.add_all(confirmations)
    
    # Receipts Creation (for multiple periods)
    receipts = [
        Receipt(lease_id=1, receipt_date=datetime.datetime(2024, 1, 5), amount=500, receipt_number="REC001", description="January 2024 Rent"),
        Receipt(lease_id=1, receipt_date=datetime.datetime(2024, 2, 5), amount=500, receipt_number="REC002", description="February 2024 Rent"),
        Receipt(lease_id=2, receipt_date=datetime.datetime(2024, 2, 6), amount=600, receipt_number="REC003", description="February 2024 Rent"),
        Receipt(lease_id=3, receipt_date=datetime.datetime(2024, 3, 5), amount=550, receipt_number="REC004", description="March 2024 Rent"),
        Receipt(lease_id=4, receipt_date=datetime.datetime(2024, 4, 5), amount=700, receipt_number="REC005", description="April 2024 Rent")
    ]
    session.add_all(receipts)

    session.commit()
    session.close()

if __name__ == "__main__":
    init_db()
    populate_mock_data()
