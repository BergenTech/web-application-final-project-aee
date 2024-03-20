#imports
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import os, io
from werkzeug.utils import secure_filename
import csv
from sqlalchemy import desc, asc
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from flask_mail import Mail
from flask_mail import Message
from flask_login import LoginManager, UserMixin
from flask_login import login_user, current_user, logout_user, login_required
import random, string
from twilio.rest import Client


app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'login' #specify the login route
# Set custom messages
login_manager.login_message = "Unauthorized Access! Please log in!"
login_manager.login_message_category = "danger"

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'emregemici@gmail.com'
# Consider using app secrets or environment variables
app.config['MAIL_PASSWORD'] = 'cxke ztxi bhac vqim'  
# Set the default sender
app.config['MAIL_DEFAULT_SENDER'] = 'eceber25@bergen.org'
mail = Mail(app)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///library.db"
db = SQLAlchemy(app)

#user model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email_verification_token = db.Column(db.String(255))
    is_verified = db.Column(db.Boolean, default=False)
    is_mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_code = db.Column(db.String(255))
    phoneNumber = db.Column(db.String(255))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Create the database tables
with app.app_context():
    db.create_all()

# Generate a Verification Token:
def generate_verification_token():
    return secrets.token_urlsafe(50)  # Adjust the token length as needed


# Send a Verification Email:
def send_verification_email(user):
    verification_link = (
        f"http://127.0.0.1:5000/verify_email/{user.email_verification_token}"
    )
    msg = Message("Verify Your Email", recipients=[user.email])
    msg.body = f"Click the following link to verify your email: {verification_link}"
    mail.send(msg)
    
# Send MFA message
def send_mfa(code):
    account_sid = 'AC82ab96ca53c90d4a9ee731e8b527068a'
    auth_token = '41b0fc3c652de108afb4d4ce90c80430'
    client = Client(account_sid, auth_token)
    message = client.messages.create(
    from_ = '+18447223757' ,
    body = code,
    to='+18777804236'
)

#routes
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/inventory', methods=["POST","GET"])
def inventory():
    #plan for this route
    #when person requests food from a card, post and then add information to a list, then go back to get to display list
    #edit/get for cart is the thing where submit buttons have different names
    #seperate route/function for commiting things to DB
    if request.method == "POST":
        if "food_picked" in request.form:
            item = request.form.get("item")
            qty = request.form.get("quanity")

    list = [["https://www.delmonte.com/sites/default/files/NSA%20Corn_1050x500_0.png", "Canned Corn", int(5)],["https://www.delmonte.com/sites/default/files/NSA%20Corn_1050x500_0.png", "Canned Corn", int(5)]]
    return render_template("inventory.html", list=list)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=["GET", "POST"])
def register():
    #Renders the registration form for users to create a new account. Upon successful registration, redirects users to the login page.
    if request.method == "POST":
        # Get form data
        name = request.form.get("name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        accept_terms = request.form.get("accept_terms")
        is_mfa_enabled = request.form.get("mfa")
        phoneNumber = request.form.get("phoneNumber")

        # Validate form data (add your own validation logic)
        if not (
            name
            and last_name
            and email
            and password
            and confirm_password
            and accept_terms
        ):
        # Handle invalid input
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")
        #handle if existing user
        user = User.query.filter_by(email=email).first()
        if user is not None and email == user.email:
            # Handle password mismatch
            flash("User already exist! Try a different email", "danger")
            return render_template("register.html")
        if password != confirm_password:
            # Handle password mismatch
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
         # Create a new user instance
        new_user = User(
            name=name,
            email=email,
            email_verification_token=generate_verification_token(),
            is_mfa_enabled= True if is_mfa_enabled else False,
            phoneNumber = phoneNumber
        )
        new_user.set_password(password)

        # Save the new user to the database
        db.session.add(new_user)
        db.session.commit()
        
        # Send the verification email
        send_verification_email(new_user)
        
        flash("Account created successfully! Please check your email to verify.", "success")
        return redirect(url_for('login'))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.email_verification_token:
                if user.is_mfa_enabled:
                    session['user_id'] =user.id
                    # Generate a random 6-digit integer
                    code = random.randint(100000, 999999)
                    user.mfa_code = code
                    db.session.commit()
                    send_mfa(code)
                    flash("Multi-Factor Authentication Code Sent!", "success")
                    return render_template("verify_mfa.html")
                else:
                    login_user(user)
                    flash("Logged in successfully!", "success")
                    return redirect(url_for('index'))
            else:
                flash("Verify your email!","warning")
        else:
            flash("Invalid credentials!","danger")
    return render_template("login.html")

# Create an Multi-Factor Authentication Route:
@app.route("/verify_mfa", methods=["GET", "POST"])
def verify_mfa():
    id = session.get('user_id')
    user = User.query.filter_by(id=id).first()
    if user:
        if request.method == 'GET':
            return render_template("verify_mfa.html")
        else:
            code = request.form.get('mfa_code')
            if user.mfa_code == code:
                user.mfa_code = None
                db.session.commit()
                login_user(user)
                flash("Logged in successfully!", "success")
                return redirect(url_for('index')) 
            else:
                flash("Incorrect Code!", "danger")
                return redirect(url_for('verify_mfa')) 
    else:
        flash("Try to login first!.", "danger")
    return redirect(url_for("login"))  # Redirect to login or home page

@app.route("/logout")
@login_required
def logout():
    logout_user() 
    flash("Logged out successfully", "success")
    return redirect(url_for("index"))



@app.route('/dashboard')
def dashboard():
    #Displays the personalized dashboard for logged-in users. Shows current donated items, reserved items, and any relevant notifications. Includes links to other functionalities such as donation form, inventory search, and profile management.
    donated_items = [""]
    reserved_items = [""]
    return render_template('dashboard.html', donated_itmes=donated_items, reserved_items=reserved_items)

@app.route('/donate', methods=['GET','POST'])
def donate():
    #Renders the donation form for users to list items they want to donate. Upon submission, processes the donation and updates the inventory accordingly. Redirects users back to the dashboard with a success message.
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        quantity = request.form.get('quantity')
        flash ('Donation successful!','success')
        return redirect(url_for('dashboard'))
    return render_template('donate.html')

@app.route('/search')
def search():
    #Renders the search page where users can search for nearby food pantries or specific items. Displays search results and allows users to view details of each pantry or item.
    return render_template('search.html')

@app.route('/profile')

def profile():
    user=current_user
    #Renders the user profile page where users can view and edit their account information. Includes sections for current deliveries, scheduled deliveries, delivery history, and edit profile details.
    return render_template('profile.html', user=user)

@app.route('/admin')
def admin():
    #Accessible only to admin users. Renders the admin panel with functionalities for managing food inventory, user accounts, donations, and generating reports. Includes forms and tools for adding or deleting items, managing users, and monitoring activity.
    return render_template('admin.html')


if __name__ == "__main__":
    app.secret_key = "super_secret_key" 
    app.run(debug=True, port="8000")