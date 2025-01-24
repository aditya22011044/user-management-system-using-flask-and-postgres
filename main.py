from flask import Flask, flash, render_template, request,redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
import hashlib

app=Flask(__name__)
app.config["SECRET_KEY"]='65b0b774279de460f1cc5c92'
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:1234@localhost:5432/mydb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"]='filesystem'
db=SQLAlchemy(app)
Session(app)

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# User Class
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True, autoincrement=True)
    fname=db.Column(db.String(255), nullable=False)
    lname=db.Column(db.String(255), nullable=False)
    email=db.Column(db.String(255), nullable=False)
    username=db.Column(db.String(255), nullable=False)
    edu=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)
    status=db.Column(db.Integer,default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.id}","{self.fname}","{self.lname}","{self.email}","{self.edu}","{self.username}","{self.status}")'

# create admin Class
class Admin(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.username}","{self.id}")'


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
                    flash('Your account is not approved by the admin.', 'danger')
                    return redirect('/user/')
                else:
                    session['user_id'] = user.id
                    session['username'] = user.username
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

# User Register
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
        else:
            is_email = User.query.filter_by(email=email).first()
            if is_email:
                flash('Email already exists', 'danger')
                return redirect('/user/signup')
            else:
                
                encoded_password = password.encode('utf-8')
                hashed_password = hashlib.sha256(encoded_password).hexdigest()

                user = User(
                    fname=fname,
                    lname=lname,
                    email=email,
                    username=username,
                    edu=edu,
                    password=hashed_password 
                )
                
                db.session.add(user)
                db.session.commit()

                flash('Account created successfully. Admin will approve your account in 10 to 30 minutes.', 'success')
                return redirect('/user/')
    else:
        return render_template('user/signup.html', title="User Signup")

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
    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        return redirect('/user/')

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
    app.run(debug=False,port=5003)
