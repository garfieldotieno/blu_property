from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import License, LicenseResetKey, Base, User, Property, Unit, Lease, PaymentReminder, PaymentConfirmation, Receipt
from new_server import create_license, fetch_licenses, fetch_license, delete_license, reset_license
from new_server import randomString, timedelta 
import datetime



from passlib.context import CryptContext
import random
import string

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

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_uid(user_type: str) -> str:
    session = SessionLocal()
    prefix = {'Admin': 'A', 'Landlord': 'L', 'Tenant': 'T'}.get(user_type, 'U')
    while True:
        uid = prefix + ''.join(random.choices(string.digits, k=4))
        if not session.query(User).filter_by(uid=uid).first():
            session.close()
            return uid
        # In case of collision, generate a new uid
        print(f"Collision detected for {uid}. Generating a new one...")

def populate_mock_data():
    session = SessionLocal()

    try:
        # Admin User Creation
        admin = User(
            uid=generate_uid("Admin"),
            user_name="AdminUser",
            email_or_phone="admin@propertyapp.com",
            password_hash=hash_password("adminpass"),
            user_type="Admin"
        )
        session.add(admin)

        # Landlord Users Creation
        landlords = [
            User(uid=generate_uid("Landlord"), user_name="LandlordOne", email_or_phone="landlord1@example.com", password_hash=hash_password("landlordpass1"), user_type="Landlord"),
            User(uid=generate_uid("Landlord"), user_name="LandlordTwo", email_or_phone="landlord2@example.com", password_hash=hash_password("landlordpass2"), user_type="Landlord"),
            User(uid=generate_uid("Landlord"), user_name="LandlordThree", email_or_phone="landlord3@example.com", password_hash=hash_password("landlordpass3"), user_type="Landlord")
        ]
        session.add_all(landlords)

        licenses = []
        
        session.add_all(licenses)

        # tenants = [
        #     User(uid=generate_uid("Tenant"), user_name="TenantOne", email_or_phone="tenant1@example.com", password_hash=hash_password("tenantpass1"), user_type="Tenant"),
        #     User(uid=generate_uid("Tenant"), user_name="TenantTwo", email_or_phone="tenant2@example.com", password_hash=hash_password("tenantpass2"), user_type="Tenant"),
        #     User(uid=generate_uid("Tenant"), user_name="TenantThree", email_or_phone="tenant3@example.com", password_hash=hash_password("tenantpass3"), user_type="Tenant"),
        #     User(uid=generate_uid("Tenant"), user_name="TenantFour", email_or_phone="tenant4@example.com", password_hash=hash_password("tenantpass4"), user_type="Tenant"),
        #     User(uid=generate_uid("Tenant"), user_name="TenantFive", email_or_phone="tenant5@example.com", password_hash=hash_password("tenantpass5"), user_type="Tenant"),
        #     User(uid=generate_uid("Tenant"), user_name="TenantSix", email_or_phone="tenant6@example.com", password_hash=hash_password("tenantpass6"), user_type="Tenant"),
        #     User(uid=generate_uid("Tenant"), user_name="TenantSeven", email_or_phone="tenant7@example.com", password_hash=hash_password("tenantpass7"), user_type="Tenant"),
        # ]
        # session.add_all(tenants)

        # # Properties Creation
        # properties = [
        #     Property(id=1, name="Property 1", landlord_id=2, description="some description"),
        #     Property(id=2, name="Property 2", landlord_id=2, description="some description"),
        #     Property(id=3, name="Property 3", landlord_id=2, description="some description"),
        #     Property(id=4, name="Property 4", landlord_id=4, description="some description"),
        #     Property(id=5, name="Property 5", landlord_id=2, description="some description"),
        #     Property(id=6, name="Property 6", landlord_id=3, description="some description"),
        # ]
        # session.add_all(properties)

        # Units Creation
        # units = [
        #     Unit(number="101", room_quantity=10, unit_type="2BedRoom", unit_description="Spacious 2 Bedroom Unit", property_id=1),
        #     Unit(number="102", room_quantity=10, unit_type="1BedRoom", unit_description="Cozy 1 Bedroom Unit", property_id=1),
        #     Unit(number="103", room_quantity=10, unit_type="1BedRoom", unit_description="Cozy 1 Bedroom Unit", property_id=1),
        #     Unit(number="104", room_quantity=10, unit_type="3BedRoom", unit_description="Large 3 Bedroom Unit", property_id=1),
        #     Unit(number="105", room_quantity=10, unit_type="2BedRoom", unit_description="Spacious 2 Bedroom Unit", property_id=1),
        #     Unit(number="106", room_quantity=10, unit_type="1BedRoom", unit_description="Cozy 1 Bedroom Unit", property_id=1),

        #     Unit(number="201", room_quantity=10, unit_type="1BedRoom", unit_description="Modern 1 Bedroom Unit", property_id=2),
        #     Unit(number="202", room_quantity=10, unit_type="2BedRoom", unit_description="Bright 2 Bedroom Unit", property_id=2),
        #     Unit(number="203", room_quantity=10, unit_type="2BedRoom", unit_description="Bright 2 Bedroom Unit", property_id=2),
        #     Unit(number="204", room_quantity=10, unit_type="3BedRoom", unit_description="Spacious 3 Bedroom Unit", property_id=2),
        #     Unit(number="205", room_quantity=10, unit_type="Studio", unit_description="Open Studio Unit", property_id=2),
        #     Unit(number="207", room_quantity=10, unit_type="2BedRoom", unit_description="Cozy 2 Bedroom Unit", property_id=2),
        #     Unit(number="208", room_quantity=10, unit_type="1BedRoom", unit_description="Modern 1 Bedroom Unit", property_id=2),

        #     Unit(number="301", room_quantity=10, unit_type="3BedRoom", unit_description="Luxurious 3 Bedroom Unit", property_id=3),
        #     Unit(number="302", room_quantity=10, unit_type="2BedRoom", unit_description="Bright 2 Bedroom Unit", property_id=3),
        #     Unit(number="303", room_quantity=10, unit_type="Studio", unit_description="Compact Studio Unit", property_id=3),
        #     Unit(number="304", room_quantity=10, unit_type="2BedRoom", unit_description="Spacious 2 Bedroom Unit", property_id=3),
        #     Unit(number="305", room_quantity=10, unit_type="1BedRoom", unit_description="Cozy 1 Bedroom Unit", property_id=3),
        #     Unit(number="306", room_quantity=10, unit_type="1BedRoom", unit_description="Modern 1 Bedroom Unit", property_id=3),
        #     Unit(number="307", room_quantity=10, unit_type="2BedRoom", unit_description="Spacious 2 Bedroom Unit", property_id=3),
        #     Unit(number="308", room_quantity=10, unit_type="3BedRoom", unit_description="Luxurious 3 Bedroom Unit", property_id=3),
        # ]
        # session.add_all(units)


        # Generate 21 leases distributed across the units
        # Generate 21 leases distributed across units with IDs between 1 and 7
        # leases = [
        #     # Tenant 5 with 3 units
        #     Lease(tenant_id=5, unit_id=1, room_number=101, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
        #     Lease(tenant_id=5, unit_id=2, room_number=102, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
        #     Lease(tenant_id=5, unit_id=3, room_number=103, start_date=datetime.datetime(2024, 2, 1), end_date=datetime.datetime(2024, 8, 31), rent_amount=600.00),

        #     # Tenant 6 with 3 units
        #     Lease(tenant_id=6, unit_id=4, room_number=104, start_date=datetime.datetime(2024, 2, 1), end_date=datetime.datetime(2024, 8, 31), rent_amount=600.00),
        #     Lease(tenant_id=6, unit_id=5, room_number=105, start_date=datetime.datetime(2024, 3, 1), end_date=datetime.datetime(2024, 11, 30), rent_amount=550.00),
        #     Lease(tenant_id=6, unit_id=6, room_number=106, start_date=datetime.datetime(2024, 4, 1), end_date=datetime.datetime(2024, 10, 31), rent_amount=650.00),

        #     # Tenant 7 with 3 units
        #     Lease(tenant_id=7, unit_id=7, room_number=201, start_date=datetime.datetime(2024, 2, 1), end_date=datetime.datetime(2024, 8, 31), rent_amount=600.00),
        #     Lease(tenant_id=7, unit_id=1, room_number=202, start_date=datetime.datetime(2024, 3, 1), end_date=datetime.datetime(2024, 11, 30), rent_amount=550.00),
        #     Lease(tenant_id=7, unit_id=2, room_number=203, start_date=datetime.datetime(2024, 4, 1), end_date=datetime.datetime(2024, 10, 31), rent_amount=650.00),

        #     # Tenant 8 with 5 units
        #     Lease(tenant_id=8, unit_id=3, room_number=204, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
        #     Lease(tenant_id=8, unit_id=4, room_number=205, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
        #     Lease(tenant_id=8, unit_id=5, room_number=207, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
        #     Lease(tenant_id=8, unit_id=6, room_number=208, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
        #     Lease(tenant_id=8, unit_id=7, room_number=301, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),

        #     # Additional leases to make a total of 21
        #     Lease(tenant_id=9, unit_id=1, room_number=302, start_date=datetime.datetime(2024, 2, 1), end_date=datetime.datetime(2024, 8, 31), rent_amount=600.00),
        #     Lease(tenant_id=9, unit_id=2, room_number=303, start_date=datetime.datetime(2024, 3, 1), end_date=datetime.datetime(2024, 11, 30), rent_amount=550.00),
        #     Lease(tenant_id=9, unit_id=3, room_number=304, start_date=datetime.datetime(2024, 4, 1), end_date=datetime.datetime(2024, 10, 31), rent_amount=650.00),
        #     Lease(tenant_id=10, unit_id=4, room_number=305, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
        #     Lease(tenant_id=10, unit_id=5, room_number=306, start_date=datetime.datetime(2024, 1, 1), end_date=datetime.datetime(2024, 12, 31), rent_amount=500.00),
        #     Lease(tenant_id=11, unit_id=6, room_number=307, start_date=datetime.datetime(2024, 2, 1), end_date=datetime.datetime(2024, 8, 31), rent_amount=600.00),
        #     Lease(tenant_id=11, unit_id=7, room_number=308, start_date=datetime.datetime(2024, 3, 1), end_date=datetime.datetime(2024, 11, 30), rent_amount=550.00),
        # ]
        # session.add_all(leases)

        

        session.commit()
        print("Mock data populated successfully!")

        
        # Generate current tenants from lease distribution
        # Generate payment reminders and confirmations
        # generate_august_payment_reminders()
        
        # generate_july_payment_confirmations()
        # generate_july_receipts_2()

        

    except Exception as e:
        print(f"An error occurred: {e}")
        session.rollback()

    finally:
        session.close()

def generate_august_payment_reminders():
    session = SessionLocal()

    try:
        # Define the payment reminders
        reminders = [
            PaymentReminder(tenant_id=1, lease_id=1, amount_due=500.00, due_date=datetime.datetime(2024, 1, 5), payment_status=0),
            PaymentReminder(tenant_id=2, lease_id=2, amount_due=600.00, due_date=datetime.datetime(2024, 2, 10), payment_status=0),
            PaymentReminder(tenant_id=3, lease_id=3, amount_due=550.00, due_date=datetime.datetime(2024, 3, 15), payment_status=0),
            PaymentReminder(tenant_id=4, lease_id=4, amount_due=500.00, due_date=datetime.datetime(2024, 4, 20), payment_status=0),
            PaymentReminder(tenant_id=5, lease_id=5, amount_due=600.00, due_date=datetime.datetime(2024, 5, 25), payment_status=0),
            PaymentReminder(tenant_id=6, lease_id=6, amount_due=650.00, due_date=datetime.datetime(2024, 6, 30), payment_status=0),
            PaymentReminder(tenant_id=7, lease_id=7, amount_due=550.00, due_date=datetime.datetime(2024, 7, 5), payment_status=0),
            PaymentReminder(tenant_id=8, lease_id=8, amount_due=600.00, due_date=datetime.datetime(2024, 8, 10), payment_status=0),
            PaymentReminder(tenant_id=9, lease_id=9, amount_due=500.00, due_date=datetime.datetime(2024, 9, 15), payment_status=0),
            PaymentReminder(tenant_id=10, lease_id=10, amount_due=500.00, due_date=datetime.datetime(2024, 10, 20), payment_status=0),
        ]

        session.add_all(reminders)
        session.commit()
        print("Payment reminders generated successfully!")

    except Exception as e:
        print(f"An error occurred while generating payment reminders: {e}")
        session.rollback()

    finally:
        session.close()




def generate_july_payment_confirmations():
    session = SessionLocal()
    confirmations = [
            PaymentConfirmation(
                lease_id=1, amount_paid=500.00,
                payment_type="MobileMoney", payment_refference="MM123456", Payment_description="January rent payment"
            ),
            PaymentConfirmation(
                lease_id=2, amount_paid=600.00,
                payment_type="BankCheque", payment_refference="BC654321", Payment_description="February rent payment"
            ),
            PaymentConfirmation(
                lease_id=3, amount_paid=550.00,
                payment_type="Cash", payment_refference="C789012", Payment_description="March rent payment"
            ),
            PaymentConfirmation(
                lease_id=4, amount_paid=500.00,
                payment_type="Crypto", payment_refference="BTC098765", Payment_description="April rent payment"
            ),
            PaymentConfirmation(
                lease_id=5, amount_paid=600.00,
                payment_type="Other", payment_refference="OTR234567", Payment_description="May rent payment"
            ),
            PaymentConfirmation(
                lease_id=6, amount_paid=650.00, 
                payment_type="MobileMoney", payment_refference="MM345678", Payment_description="June rent payment"
            ),
            PaymentConfirmation(
                lease_id=7, amount_paid=550.00,
                payment_type="BankCheque", payment_refference="BC876543", Payment_description="July rent payment"
            ),
            PaymentConfirmation(
                lease_id=8, amount_paid=600.00, 
                payment_type="Cash", payment_refference="C123456", Payment_description="August rent payment"
            ),
            PaymentConfirmation(
                lease_id=9, amount_paid=500.00, 
                payment_type="Crypto", payment_refference="ETH567890", Payment_description="September rent payment"
            ),
            PaymentConfirmation(
                lease_id=10, amount_paid=500.00, 
                payment_type="Other", payment_refference="OTR890123", Payment_description="October rent payment"
            ),
        ]
    
    try:
        # Define the payment confirmations with the updated fields
        session.add_all(confirmations)
        session.commit()
        print("Payment confirmations generated successfully!")

    except Exception as e:
        print(f"An error occurred while generating payment confirmations: {e}")
        session.rollback()

    finally:
        session.close()


def generate_july_receipts_2():
    session = SessionLocal()

    try:
        # Define the mock receipt data for July
        confirmations = session.query(PaymentConfirmation).all()
        receipts = []
        for confirmation in confirmations:
            receipt_number = f"RCPT-{random.randint(100000, 999999)}"
            receipt = Receipt(
                lease_id=confirmation.lease_id,
                receipt_date=confirmation.created_at,
                amount=confirmation.amount_paid,
                receipt_number=receipt_number,
                description=f"Receipt for {confirmation.Payment_description}"
            )
            receipts.append(receipt)

        session.add_all(receipts)
        session.commit()
        print("Receipts for July generated successfully!")

    except Exception as e:
        print(f"An error occurred while generating July receipts: {e}")
        session.rollback()

    finally:
        session.close()


def test_create_license(input_license_type, days):
    key = randomString(16)
    print(f"generating license_key : {key}")
    create_license({"license_key":key, "license_type":input_license_type, "license_status":True, "license_expiry":datetime.datetime.now() + timedelta(days=days)})
    

def test_validate_reset_key(input_key_value, input_license_type):
    print("Validating reset key")

    # use LicenseResetKey class to validate the key
    if LicenseResetKey.is_valid_key(input_key_value):
        # If the key is valid, redirect to /
        print("Valid reset key")
        # check if License table has any record,
        # if yes, delete all records and create new record
        # if no, create new record
        if input_license_type == "Full":
            days = 366
        else:
            days = 183

        l = fetch_licenses()
 
        if l == []:
            # if input_license_type == "Full", days = 366 else 188
            create_license({"license_key":randomString(16), "license_type":input_license_type, "license_status":True, "license_expiry":datetime.datetime.now() + timedelta(days=days)})
        else:
            print(f"during reseting l was {l}")
            delete_license(1)
            create_license({"license_key":randomString(16), "license_type":input_license_type, "license_status":True, "license_expiry":datetime.datetime.now() + timedelta(days=days)})

        
        return {
            "message":"License reset successful",
        }
        
    else:
        # If the key is invalid, load the flash message and redirect to /
        return {
            "message":"Invalid reset key"
        }
     

if __name__ == "__main__":
    init_db()
    populate_mock_data()
