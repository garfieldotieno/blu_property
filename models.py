from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Numeric, Enum, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime
import pydantic
import hashlib
import yaml 

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(10), unique=True, nullable=False)
    user_name = Column(String(20), unique=True, nullable=False)
    
    email_or_phone = Column(String, unique=True, index=True)
    password_hash = Column(String(100), nullable=False)
    
    user_type = Column(Enum('Admin', 'Landlord', 'Tenant', 'Regular_visitor', name='user_types'))
    suspended = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Move relationships to the end
    sessions = relationship('Session', back_populates='user')
    properties = relationship('Property', back_populates='landlord')
    leases = relationship('Lease', back_populates='tenant')
    # units = relationship('Units', back_populates='tenant')


class Otp(Base):
    __tablename__ = 'otps'

    id = Column(Integer, primary_key=True, index=True)
    otp = Column(String, unique=True, index=True)

    # Added: User email
    user_email = Column(String, nullable=False)

    # Added: Is active up to (usually one day)
    is_active_upto = Column(DateTime, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(days=1))

    user_type = Column(Enum('landlord', 'tenant', name='otp_user_types'))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class Session(Base):
    __tablename__ = 'sessions'

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    expires_at = Column(DateTime)

    user = relationship('User', back_populates='sessions')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class License(Base):
    __tablename__ = "License"

    id = Column(Integer, primary_key=True)
    uid = Column(String(10), unique=True, nullable=False)
    license_key = Column(String(20), unique=True, nullable=False)
    license_type = Column(String(10), nullable=False)
    license_status = Column(Boolean, nullable=False)
    license_expiry = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now())
    updated_at = Column(DateTime, default=datetime.datetime.now())

    def __repr__(self):
        return f"License(id={self.id}, uid='{self.uid}', license_key='{self.license_key}', license_type='{self.license_type}', license_status='{self.license_status}', license_expiry='{self.license_expiry}', created_at={self.created_at}, updated_at={self.updated_at})"


class LicenseResetKey(pydantic.BaseModel):
    license_key: str

    @staticmethod
    def save_key(license_key):
        # Hash the license key using SHA-256
        hashed_key = hashlib.sha256(license_key.encode()).hexdigest()
        
        # Load existing keys from .pos_key.yml if it exists
        existing_keys = LicenseResetKey.fetch_keys()

        # check if existing list is of length 20
        # if length is 20, delete the entire list and append the new, otherwise append to existing list
        if len(existing_keys) == 20:
            existing_keys = []
            existing_keys.append(hashed_key)

        else:
            existing_keys.append(hashed_key)
        
             # Save the updated list of hashed keys back to .pos_key.yml
        with open('.pos_keys.yml', 'w') as file:
            yaml.dump(existing_keys, file)


    @staticmethod
    def fetch_keys():
        try:
            with open('.pos_keys.yml', 'r') as file:
                return yaml.safe_load(file) or []
        except FileNotFoundError:
            # If the file does not exist, return an empty list
            return []

    @staticmethod
    def delete_key(license_key):
        # Hash the license key to match the stored format
        hashed_key = hashlib.sha256(license_key.encode()).hexdigest()

        # Fetch the existing keys
        existing_keys = LicenseResetKey.fetch_keys()

        # Remove the hashed key if it exists
        if hashed_key in existing_keys:
            existing_keys.remove(hashed_key)

            # Save the updated list of hashed keys back to .pos_key.yml
            with open('.pos_keys.yml', 'w') as file:
                yaml.dump(existing_keys, file)

    @staticmethod
    def is_valid_key(license_key):
        # Hash the license key to match the stored format
        hashed_key = hashlib.sha256(license_key.encode()).hexdigest()

        # Fetch the existing keys
        existing_keys = LicenseResetKey.fetch_keys()

        # Check if the hashed key exists in the list
        return hashed_key in existing_keys


class Property(Base):

    __tablename__ = 'properties'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String, nullable=False)
    landlord_id = Column(Integer, ForeignKey('users.id'))
    suspended = Column(Boolean, default=False)

    landlord = relationship('User', back_populates='properties')
    units = relationship('Unit', back_populates='property')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description":self.description,
            "landlord_id": self.landlord_id,
            "suspended": self.suspended,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "units": [unit.id for unit in self.units]  # List of related unit IDs
        }


class Unit(Base):
    __tablename__ = 'units'

    id = Column(Integer, primary_key=True, index=True)
    number = Column(String)
    room_quantity = Column(Integer, nullable=False)
    unit_type = Column(Enum("Studio", "1BedRoom", "2BedRoom", "3BedRoom", "Shop"), nullable=False)
    unit_description = Column(String, nullable=False)
    property_id = Column(Integer, ForeignKey('properties.id'))
    tenant_id = Column(Integer, ForeignKey('users.id'))
    suspended = Column(Boolean, default=False)

    # tenant = relationship('User', back_populates='units')   
    property = relationship('Property', back_populates='units')
    lease = relationship('Lease', uselist=False, back_populates='unit')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "number": self.number,
            "room_quantity": self.room_quantity,
            "unit_type": self.unit_type,
            "unit_description": self.unit_description,
            "property_id": self.property_id,
            "tenant_id": self.tenant_id,
            "suspended": self.suspended,
            "lease_id": self.lease.id if self.lease else None,  # ID of the related lease, if any
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class Lease(Base):
    __tablename__ = 'leases'

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey('users.id'))
    unit_id = Column(Integer, ForeignKey('units.id'))
    room_number = Column(Integer, nullable=False)

    start_date = Column(DateTime)
    end_date = Column(DateTime)
    rent_amount = Column(Numeric)

    tenant = relationship('User', back_populates='leases')
    unit = relationship('Unit', back_populates='lease')
    reminders = relationship('PaymentReminder', back_populates='lease')
    confirmations = relationship('PaymentConfirmation', back_populates='lease')
    receipts = relationship('Receipt', back_populates='lease')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "unit_id": self.unit_id,
            "unit_room_number":self.room_number,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "rent_amount": float(self.rent_amount) if self.rent_amount else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "reminders": [reminder.id for reminder in self.reminders],  # List of related reminder IDs
            "confirmations": [confirmation.id for confirmation in self.confirmations],  # List of related confirmation IDs
            "receipts": [receipt.id for receipt in self.receipts]  # List of related receipt IDs
        }
    

class PaymentReminder(Base):
    __tablename__ = 'payment_reminders'

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer)
    lease_id = Column(Integer, ForeignKey('leases.id'))
    amount_due = Column(Float, nullable=False)
    due_date = Column(DateTime, nullable=False)
    payment_status = Column(Boolean)
    payment_confirmation_issued = Column(Boolean, default=False)

    lease = relationship('Lease', back_populates='reminders')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'tenant_id': self.tenant_id,
            'lease_id': self.lease_id,
            'amount_due': self.amount_due,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'payment_status': self.payment_status,
            'payment_confirmation_issued': self.payment_confirmation_issued,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    


class PaymentConfirmation(Base):
    __tablename__ = 'payment_confirmations'

    id = Column(Integer, primary_key=True, index=True)
    lease_id = Column(Integer, ForeignKey('leases.id'))
    payment_reminder_id = Column(Integer, ForeignKey('payment_reminders.id'))
    amount_paid = Column(Float, nullable=False)
    payment_type = Column(Enum('MobileMoney', "BankCheque", "Cash", "Crypto", "Other"))
    payment_refference = Column(String)
    Payment_description = Column(String)
    payment_cleared = Column(Boolean, default=False)

    lease = relationship('Lease', back_populates='confirmations')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id":self.id,
            "lease_id":self.lease_id,
            "payment_reminder_id":self.payment_reminder_id,
            "amount_paid":self.amount_paid,
            "payment_type":self.payment_type,
            "payment_refference":self.payment_refference,
            "payment_description":self.Payment_description,
            "payment_cleared" : self.payment_cleared
        } 


class Receipt(Base):
    __tablename__ = 'receipts'

    id = Column(Integer, primary_key=True, index=True)
    receipt_number = Column(String, unique=True)
    confirmation_id = Column(Integer, unique=True)

    lease_id = Column(Integer, ForeignKey('leases.id'))
    receipt_date = Column(DateTime, default=datetime.datetime.utcnow)
    amount = Column(Float, nullable=False)
    description = Column(String)

    lease = relationship('Lease', back_populates='receipts')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'receipt_number': self.receipt_number,
            'confirmation_id': self.confirmation_id,
            'lease_id': self.lease_id,
            'receipt_date': self.receipt_date.isoformat() if self.receipt_date else None,
            'amount': self.amount,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        } 