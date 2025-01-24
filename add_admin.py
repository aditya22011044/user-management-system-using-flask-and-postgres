from main import app, db, Admin
import hashlib

def add_admin():
    with app.app_context():
#        username = "admin"
#        password = "admin123"

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        existing_admin = Admin.query.filter_by(username=username).first()
        if not existing_admin:
            new_admin = Admin(username=username, password=hashed_password)
            db.session.add(new_admin)
            db.session.commit()
            print("Admin added successfully!")
        else:
            print("Admin already exists!")

if __name__ == "__main__":
    add_admin()
