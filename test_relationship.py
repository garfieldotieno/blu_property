import unittest
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, Session, Property, Unit, Lease, PaymentReminder, PaymentConfirmation, Receipt

# Configure database URL
DATABASE_URL = "sqlite:///property.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

db_session = SessionLocal()

def find_landlord_user_relationships(session, user_id):
    user = db_session.query(User).filter_by(id=user_id).first()
    if not user:
        return {
            "sessions": [], 
            "properties": [], 
            # "leases": []
            }

    sessions = db_session.query(Session).filter_by(user_id=user_id).all()
    properties = session.query(Property).filter_by(landlord_id=user_id).all()
    leases = session.query(Lease).filter_by(tenant_id=user_id).all()
    
    return {
        "sessions": [session.to_dict() for session in sessions],
        "properties": [property.to_dict() for property in properties],
        # "leases": [lease.to_dict() for lease in leases]
    }

def find_property_relationships(session, property_id):
    property_ = session.query(Property).filter_by(id=property_id).first()
    if not property_:
        return {
            "units": [], 
            # "leases": []
            }

    units = session.query(Unit).filter_by(property_id=property_id).all()
    leases = session.query(Lease).join(Unit).filter(Unit.property_id == property_id).all()
    
    return {
        "units": [unit.to_dict() for unit in units ],
        # "leases": [lease.to_dict() for lease in leases ]
    }


def find_unit_relationships(session, unit_id):
    unit = session.query(Unit).filter_by(id=unit_id).first()
    if not unit:
        return {"lease": None}

    lease = session.query(Lease).filter_by(unit_id=unit_id).first()
    
    return {
        "lease": lease.to_dict()
    }


def find_tenant_user_relationships(session, tenant_id):
    user = db_session.query(User).filter_by(id=tenant_id).first()
    if not user:
        return {"sessions":[], "leases":[]}
    
    sessions = db_session.query(Session).filter_by(user_id=tenant_id).all()
    leases = db_session.query(Lease).filter_by(tenant_id=tenant_id).all()
    units = db_session.query(Unit).filter_by(tenant_id=tenant_id).all()

    return {
        "session": [session.to_dict() for session in sessions],
        "leases": [lease.to_dict() for lease in leases ],
        # unit info is in lease record
    }


def find_lease_relationships(session, lease_id):
    lease = session.query(Lease).filter_by(id=lease_id).first()
    if not lease:
        return {"payment_reminders": [], "payment_confirmations": [], "receipts": []}

    payment_reminders = session.query(PaymentReminder).filter_by(lease_id=lease_id).all()
    payment_confirmations = session.query(PaymentConfirmation).filter_by(lease_id=lease_id).all()
    receipts = session.query(Receipt).filter_by(lease_id=lease_id).all()
    
    return {
        "payment_reminders": payment_reminders,
        "payment_confirmations": payment_confirmations,
        "receipts": receipts
    }


def find_payment_reminder_relationships(session, payment_reminder_id):
    reminders = session.query(PaymentReminder).filter_by(id=payment_reminder_id)
    if not reminders:
        return {"lease":[]}
    
    lease = session.query(Lease).filter_by(id=payment_reminder_id)
    return {
        "lease":lease
    }

def find_payment_confirmation_relationships(session, payment_confirmation_id):
    confirmations = session.query(PaymentConfirmation).filter_by(id=payment_confirmation_id)
    if not confirmations :
        return {"lease":[]}
    
    lease = session.query(Lease).filter_by(id=payment_confirmation_id)

def get_all_user_relationship():
    users = db_session.query(User).all()
    for user in users:
        landlord_relationships = {}
        tenant_relationships = {}
        relationships = {}

        if user.user_type == "Landlord":
            landlord_relationships = find_landlord_user_relationships(db_session, user.id)
            relationships = landlord_relationships
            
        elif user.user_type == "Tenant":
            tenant_relationships = find_tenant_user_relationships(db_session, user.id)
            relationships = tenant_relationships

        print("\n")
        print(f"user {user.id} type : {user.user_type} relationships: {relationships}\n")

        
def get_all_property_relationships():
    properties = db_session.query(Property).all()
    for property in properties:
        relationships = find_property_relationships(db_session, property.id)
        print(f"property {property.id} relationships : {relationships}\n")


def get_all_unit_relationships():
    units = db_session.query(Unit).all()
    for unit in units:
        relationships = find_unit_relationships(db_session, unit.id)
        print(f"unit id : {unit.id} relationships : {relationships}\n")


def get_all_lease_relationships():
    leases = db_session.query(Lease).all()
    for lease in leases:
        relationships = find_lease_relationships(db_session, lease.id)
        print(f"lease id : {lease.id} relationships : {relationships}\n")


def new_test_payment_reminders():
    payment_reminders = db_session.query(PaymentReminder).all()
    for payment_reminder in payment_reminders:
        relationships = find_payment_reminder_relationships(db_session, payment_reminder.id)
        print(f"payment_reminder id : {payment_reminder.id} relationships : {relationships}\n")
     

def new_test_payment_confirmations():
    payment_confirmations = db_session.query(PaymentConfirmation).all()
    for payment_confirmation in payment_confirmations:
        relationships = find_payment_confirmation_relationships(db_session, payment_confirmation.id)
        print(f"payment_confirmation id : {payment_confirmation.id} relationships : {relationships}\n")
    

if __name__ == "__main__":
    get_all_user_relationship()
    get_all_property_relationships()

    get_all_unit_relationships()
    get_all_lease_relationships()
