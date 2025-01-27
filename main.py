from flask import Flask, flash, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
import hashlib
import os
from datetime import datetime
from flask_migrate import Migrate
from datetime import timedelta
from flask_mail import Mail
import random
import string
from flask_mail import Message
from email_utils import generate_otp, send_otp_email


app=Flask(__name__)
app.config["SECRET_KEY"]='65b0b774279de460f1cc5c92'
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://aditya_atole:w1d57XHXae0mNI9Wsexpn0cu11w0rHLH@dpg-cu9o6edds78s739gimgg-a.oregon-postgres.render.com/mydb_jkwq'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config["SESSION_PERMANENT"] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.config["SESSION_TYPE"] = 'filesystem'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = aditya.22011044@viit.ac.in
app.config['MAIL_PASSWORD'] = ylmcckchqxptoxmt
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = no-reply@gmail.com

mail = Mail(app)
db=SQLAlchemy(app)
migrate = Migrate(app, db)
Session(app)

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# User Class
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True, autoincrement=True)
    fname=db.Column(db.String(255), nullable=False)
    lname=db.Column(db.String(255), nullable=False)
    email=db.Column(db.String(255), nullable=False, unique=True)
    username=db.Column(db.String(255), nullable=False, unique=True)
    edu=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)
    status=db.Column(db.Integer,default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.id}","{self.fname}","{self.lname}","{self.email}","{self.edu}","{self.username}","{self.status}")'

# create admin Class
class Admin(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(255), nullable=False, unique=True)
    password=db.Column(db.String(255), nullable=False, unique=True)

    def __repr__(self):
        return f'Admin("{self.username}","{self.id}")'

@app.before_request
def check_session_timeout():
    if 'user_id' in session:
        last_activity = session.get('last_activity')

        if last_activity is None:
            session['last_activity'] = datetime.now()
            return

        session_lifetime = timedelta(minutes=10)
        if datetime.now() - last_activity > session_lifetime:
            session.clear()
            flash('Your session has expired due to inactivity. Please log in again.', 'danger')
            return redirect('/user/')

        session['last_activity'] = datetime.now()


@app.route('/')
def index():
    return render_template('index.html',title="")


#Admin login
@app.route('/admin/', methods=["POST", "GET"])
def adminIndex():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == "" or password == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/admin/')
        else:
            admin = Admin.query.filter_by(username=username).first()
            if admin:
                encoded_password = password.encode('utf-8')
                hashed_password = hashlib.sha256(encoded_password).hexdigest()

                if admin.password == hashed_password:
                    session['admin_id'] = admin.id
                    session['admin_name'] = admin.username
                    session.permanent = True
                    flash('Login successful!', 'success')
                    return redirect('/admin/dashboard')
                else:
                    flash('Invalid username or password', 'danger')
                    return redirect('/admin/')
            else:
                flash('Invalid username or password', 'danger')
                return redirect('/admin/')
    else:
        return render_template('admin/index.html', title="Admin Login")

# Admin Dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser=User.query.count()
    totalApprove=User.query.filter_by(status=1).count()
    NotTotalApprove=User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html',title="Admin Dashboard",totalUser=totalUser,totalApprove=totalApprove,NotTotalApprove=NotTotalApprove)

# Admin get all user
@app.route('/admin/get-all-user', methods=["POST","GET"])
def adminGetAllUser():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if request.method== "POST":
        search=request.form.get('search')
        users=User.query.filter(User.username.like('%'+search+'%')).all()
        return render_template('admin/all-user.html',title='Approve User',users=users)
    else:
        users=User.query.all()
        return render_template('admin/all-user.html',title='Approve User',users=users)

#Approve user
@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')
    User().query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    flash('Approve Successfully','success')
    return redirect('/admin/get-all-user')

# disapprove user
@app.route('/admin/disapprove-user/<int:id>')
def adminDisapprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')

    user = User.query.filter_by(id=id).first()
    if user:
        user.status = 0
        db.session.commit()
        flash('User disapproved successfully', 'success')
    else:
        flash('User not found', 'danger')
    return redirect('/admin/get-all-user')

# Delete User
@app.route('/admin/delete-user/<int:id>', methods=['POST', 'GET'])
def adminDeleteUser(id):
    if not session.get('admin_id'):
        return redirect('/admin/')

    user = User.query.filter_by(id=id).first()

    if user:
        try:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error occurred while deleting user: {str(e)}', 'danger')
    else:
        flash('User not found', 'danger')

    return redirect('/admin/get-all-user')


# Change admin password
@app.route('/admin/change-admin-password', methods=["POST", "GET"])
def adminChangePassword():
    admin = Admin.query.get(1)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == "" or password == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/admin/change-admin-password')
        else:
            encoded_password = password.encode('utf-8')
            hashed_password = hashlib.sha256(encoded_password).hexdigest()
            Admin.query.filter_by(username=username).update(dict(password=hashed_password))
            db.session.commit()
            
            flash('Admin password updated successfully', 'success')
            return redirect('/admin/change-admin-password')

    return render_template('admin/admin-change-password.html', title='Admin Change Password', admin=admin)

# Admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if session.get('admin_id'):
        session['admin_id']=None
        session['admin_name']=None
        return redirect('/')

# User login
@app.route('/user/', methods=["POST", "GET"])
def userIndex():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            encoded_password = password.encode('utf-8')
            hashed_password = hashlib.sha256(encoded_password).hexdigest()

            if user.password == hashed_password:
                if user.status == 0:
                    flash('Your account is not approved by the admin. Please wait for approval.', 'danger')
                    return redirect('/user/')
                else:
                    session['user_id'] = user.id
                    session['username'] = user.username
                    session.permanent = True
                    flash('Login successful!', 'success')
                    return redirect('/user/dashboard')
            else:
                flash('Invalid email or password.', 'danger')
                return redirect('/user/')
        else:
            flash('Invalid email or password.', 'danger')
            return redirect('/user/')
    else:
        return render_template('user/index.html', title="User Login")


@app.route('/user/signup', methods=['POST', 'GET'])
def userSignup():
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        edu = request.form.get('edu')
        password = request.form.get('password')

        if fname == "" or lname == "" or email == "" or password == "" or username == "" or edu == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/user/signup')
        
        is_username = User.query.filter_by(username=username).first()
        if is_username:
            flash('Username already exists', 'danger')
            return redirect('/user/signup')

        is_email = User.query.filter_by(email=email).first()
        if is_email:
            flash('Email already exists', 'danger')
            return redirect('/user/signup')
        else:
            session['temp_user'] = {
                'fname': fname,
                'lname': lname,
                'email': email,
                'username': username,
                'edu': edu,
                'password': password
            }

            otp = generate_otp()

            if send_otp_email(mail, email, otp):
                session['otp'] = otp
                session['email'] = email
                flash('OTP sent to your email. Please verify to complete registration.', 'success')
                return redirect('/user/verify-otp')
            else:
                flash('Failed to send OTP. Try again later.', 'danger')
                return redirect('/user/signup')
    else:
        return render_template('user/signup.html', title="User Signup")



@app.route('/user/verify-otp', methods=['POST', 'GET'])
def verifyOtp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        if entered_otp == session.get('otp'):

            user_data = session.get('temp_user')

            if user_data:
                encoded_password = user_data['password'].encode('utf-8')
                hashed_password = hashlib.sha256(encoded_password).hexdigest()

                user = User(
                    fname=user_data['fname'],
                    lname=user_data['lname'],
                    email=user_data['email'],
                    username=user_data['username'],
                    edu=user_data['edu'],
                    password=hashed_password,
                    status=0
                )

                db.session.add(user)
                db.session.commit()

                session.pop('temp_user', None)
                session.pop('otp', None)
                session.pop('email', None)

                flash('Email verified successfully! Admin will approve you access in 10 to 30 minutes', 'success')
                return redirect('/')
            else:
                flash('User data not found. Please try again.', 'danger')
                return redirect('/user/verify-otp')
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect('/user/verify-otp')

    return render_template('user/verify_otp.html', title="Verify OTP")


# user dashboard
@app.route('/user/dashboard')
def userDashboard():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User().query.filter_by(id=id).first()
    return render_template('user/dashboard.html',title="User Dashboard",users=users)

# User logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')
    
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect('/')

# User change password
@app.route('/user/change-password', methods=["POST", "GET"])
def userChangePassword():
    if not session.get('user_id'):
        return redirect('/user/')
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email == "" or password == "":
            flash('Please fill in all fields', 'danger')
            return redirect('/user/change-password')
        else:
            user = User.query.filter_by(email=email).first()

            if user:
                encoded_password = password.encode('utf-8')
                hashed_password = hashlib.sha256(encoded_password).hexdigest()
                User.query.filter_by(email=email).update(dict(password=hashed_password))
                db.session.commit()

                flash('Password changed successfully', 'success')
                return redirect('/user/change-password')

            else:
                flash('Invalid email', 'danger')
                return redirect('/user/change-password')

    else:
        return render_template('user/change-password.html', title="Change Password")

@app.route('/user/delete-account', methods=['POST', 'GET'])
def delete_account():
    if not session.get('user_id'):
        return redirect('/user/')

    if request.method == 'POST':
        user = User.query.get(session['user_id'])

        if user:
            otp = generate_otp()

            if send_otp_email(mail, user.email, otp):
                session['delete_otp'] = otp
                session['email'] = user.email
                flash('An OTP has been sent to your email for verification.', 'success')
                return redirect('/user/verify-otp-delete')
            else:
                flash('Failed to send OTP. Try again later.', 'danger')
                return redirect('/user/')
        else:
            flash('User not found.', 'danger')
            return redirect('/user/')

    return render_template('user/delete_account.html', title="Delete Account")


@app.route('/user/verify-otp-delete', methods=['POST', 'GET'])
def verify_otp_delete():
    if not session.get('user_id'):
        return redirect('/user/')

    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        if entered_otp == session.get('delete_otp'):
            email = session.get('email')
            user = User.query.filter_by(email=email).first()

            if user:
                db.session.delete(user)
                db.session.commit()
                flash('Your account has been successfully deleted.', 'success')
                return redirect('/user/logout')
            else:
                flash('User not found. Please try again.', 'danger')
                return redirect('/user/verify-otp-delete')
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect('/user/verify-otp-delete')

    return render_template('user/verify_otp_delete.html', title="Verify OTP for Deletion")


# user update profile
@app.route('/user/update-profile', methods=["POST", "GET"])
def userUpdateProfile():
    if not session.get('user_id'):
        return redirect('/user/')
    
    id = session.get('user_id')
    users = User.query.get(id)

    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        edu = request.form.get('edu')

        if fname == "" or lname == "" or email == "" or username == "" or edu == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/user/update-profile')
        else:
            users.fname = fname
            users.lname = lname
            users.email = email
            users.username = username
            users.edu = edu
            db.session.commit()

            session['username'] = username

            flash('Profile updated successfully', 'success')
            return redirect('/user/dashboard')
    else:
        return render_template('user/update-profile.html', title="Update Profile", users=users)


if __name__=="__main__":
    app.run(debug=True,port=5003)
