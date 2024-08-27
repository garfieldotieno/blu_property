from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Numeric, Enum, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

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


class Otp(Base):
    __tablename__ = 'otps'

    id = Column(Integer, primary_key=True, index=True)
    otp = Column(String, unique=True, index=True)
    # add : user_email
    # add : is_active_upto
    
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


class Property(Base):
    __tablename__ = 'properties'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    landlord_id = Column(Integer, ForeignKey('users.id'))
    suspended = Column(Boolean, default=False)

    landlord = relationship('User', back_populates='properties')
    units = relationship('Unit', back_populates='property')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class Unit(Base):
    __tablename__ = 'units'

    id = Column(Integer, primary_key=True, index=True)
    number = Column(String)
    property_id = Column(Integer, ForeignKey('properties.id'))
    suspended = Column(Boolean, default=False)

    property = relationship('Property', back_populates='units')
    lease = relationship('Lease', uselist=False, back_populates='unit')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class Lease(Base):
    __tablename__ = 'leases'

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey('users.id'))
    unit_id = Column(Integer, ForeignKey('units.id'))
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


class PaymentReminder(Base):
    __tablename__ = 'payment_reminders'

    id = Column(Integer, primary_key=True, index=True)
    lease_id = Column(Integer, ForeignKey('leases.id'))
    reminder_date = Column(DateTime)

    lease = relationship('Lease', back_populates='reminders')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class PaymentConfirmation(Base):
    __tablename__ = 'payment_confirmations'

    id = Column(Integer, primary_key=True, index=True)
    lease_id = Column(Integer, ForeignKey('leases.id'))
    confirmation_date = Column(DateTime)
    payment_details = Column(String)

    lease = relationship('Lease', back_populates='confirmations')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class Receipt(Base):
    __tablename__ = 'receipts'

    id = Column(Integer, primary_key=True, index=True)
    lease_id = Column(Integer, ForeignKey('leases.id'))
    receipt_date = Column(DateTime)
    amount = Column(Numeric)
    receipt_number = Column(String, unique=True)
    description = Column(String)

    lease = relationship('Lease', back_populates='receipts')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
