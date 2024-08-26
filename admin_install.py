from server import app, db, user_datastore
from flask_security.utils import hash_password

with app.app_context():
    db.create_all()

    # Create roles
    admin_role = user_datastore.find_or_create_role('admin')
    landlord_role = user_datastore.find_or_create_role('landlord')
    tenant_role = user_datastore.find_or_create_role('tenant')

    # Create admin user
    if not user_datastore.find_user(email="admin@example.com"):
        user_datastore.create_user(
            email="admin@example.com",
            password=hash_password("adminpassword"),
            roles=[admin_role]
        )

    db.session.commit()
