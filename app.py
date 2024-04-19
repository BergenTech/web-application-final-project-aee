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
app.config['MAIL_DEFAULT_SENDER'] = 'emregemici@gmail.com'
mail = Mail(app)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///library.db"
db = SQLAlchemy(app)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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


class Inventory(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    qty = db.Column(db.Integer)
    description = db.Column(db.String(255)) 
    bank = db.Column(db.String)
    tags = db.Column(db.String(255)) 

    def __repr__(self):
        db.create.all()

#Donation model
class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    item_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(255))  
    status = db.Column(db.String(20), default='pending')
    tags = db.Column(db.String(255))  


    def __repr__(self):
        return f"Donation(id={self.id}, item_name='{self.item_name}', quantity={self.quantity}), description={self.description}"

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))  
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')

    def __repr__(self):
        return f"Request(id={self.id}, item_name='{self.item_name}', quantity={self.quantity}), description={self.description}"

# Create the database tables
with app.app_context():
    db.create_all()

# Generate a Verification Token:
def generate_verification_token():
    return secrets.token_urlsafe(50)  # Adjust the token length as needed

@app.route("/verify_email/<token>", methods=["GET"])
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()
    if user:
        user.email_verification_token = None  # Mark email as verified
        # Set a flag or column in the User model to indicate verified status
        user.is_verified = True  
        db.session.commit()
        flash("Email verified successfully!", "success")
    else:
        flash("Invalid verification token.", "danger")
    return redirect(url_for("login"))  # Redirect to login or home page

# Send a Verification Email:
def send_verification_email(user):
    verification_link = (
        f"https://63hsl2h0-1000.use.devtunnels.ms/verify_email/{user.email_verification_token}"
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
@login_required
def inventory():
    all_inventory = Inventory.query.all()
    cart = session.get('cart', [])
    if request.method == "POST":
        if "food_picked" in request.form:
            item = request.form.get("item")
            object = Inventory.query.filter_by(name=item).first()
            qty = int(request.form.get("qty"))
            if qty > object.qty:
                flash(f"Please request a less than or equal amount of {item}'s quantity of {object.qty}", "danger")
                session['cart'] = cart
                return render_template("inventory.html", invent_list=all_inventory, cart=cart)
            cart.append([item, qty])
            flash(f"Added {qty} {item} to cart", "success")
        elif "checkout" in request.form:
            for item in cart:
                try:
                    # object.qty=int(object.qty -item[1])
                    new_request = Request(item_name=item[0], quantity=item[1], email=current_user.email)
                    # Save the new donation to the database
                    db.session.add(new_request)
                    print('almost')
                    db.session.commit()
                    print('committed!!!')
                    # send_donation_notification_to_admin(new_request)
                    
                except Exception as e:
                    print('Error:', str(e))
                    db.session.rollback()
                    flash("There was an issue somewhere", "danger")
                    return render_template("inventory.html", invent_list=all_inventory, cart=cart)
            flash(f"Requested your items from default bank", "success")
            session['cart'].clear()
        elif "delete_cart_item" in request.form:
            item_index = int(request.form.get('item_index'))
            print(item_index)
            del session['cart'][item_index-1]
            flash("Item removed successfully", "success")
        elif "search" in request.form:
            search_text = request.form["search_text"]
            all_inventory = Inventory.query.filter(
                getattr(Inventory, "name").ilike(f"%{search_text}%")
            ).all()
            return render_template("inventory.html", invent_list=all_inventory, cart=cart)

            
            
    session['cart'] = cart
    return render_template("inventory.html", invent_list=all_inventory, cart=cart)

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
            last_name=last_name,
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
                    session["user_ID"]= user.id
                    # Generate a random 6-digit integer
                    code = random.randint(100000, 999999)
                    user.mfa_code = code
                    db.session.commit()
                    send_mfa(code)
                    flash("Multi-Factor Authentication Code Sent!", "success")
                    return render_template("verify_mfa.html")
                else:
                    login_user(user)
                    session['user_ID'] =user.id
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

def send_donation_notification_to_admin(donation):
    admin_email = "mseceberrak@gmail.com"  # Replace with actual admin email
    msg = Message("New Pending Donation", recipients=[admin_email])
    msg.body = f"New pending donation:\nItem: {donation.item_name}\nQuantity: {donation.quantity}\nDescription: {donation.description}"
    mail.send(msg)

@app.route('/donate', methods=['GET','POST'])
@login_required
def donate():
    user=current_user
    id=user.id
    if request.method == 'POST':
        
        item_name = request.form.get('item_name')
        quantity = request.form.get('quantity')
        description = request.form.get('description')

        # Validate form data
        if not (item_name and quantity):
            flash("Please fill in all fields.", "danger")
            return redirect(url_for('donate'))

        try:
            # Create a new donation instance
            new_donation = Donation(item_name=item_name, quantity=quantity, description=description, id=id)

            # Save the new donation to the database
            db.session.add(new_donation)
            db.session.commit()
            
            send_donation_notification_to_admin(new_donation)


            flash("Donation successful! Thank you for your contribution.", "success")
            user = current_user
            donated_items = Donation.query.filter_by(id=user.id).all() 
            
            return render_template('profile.html', user=user, donated_items=donated_items) 
        except Exception as e:
            # Handle database errors or other exceptions
            # flash("An error occurred while processing your donation. Please try again later.", "danger")
            app.logger.error(f"Error processing donation: {e}")
            return redirect(url_for('donate'))
    return render_template('donate.html')

@app.route('/search', methods=['GET','POST'])
def search():
    if request.method == 'POST':
        #Search logic here
            search_query = request.form.get('search_query')

        # Placeholder example for search results
        # Replace this with actual search functionality based on your application's requirements
        # For demonstration purposes, we're just returning some dummy search results
            search_results = [
                {'name': 'Food Pantry 1', 'location': '123 Main Street'},
                {'name': 'Food Pantry 2', 'location': '456 Elm Street'},
            {   'name': 'Food Pantry 3', 'location': '789 Oak Street'}
        ]

            return render_template('search.html', search_results=search_results)    
    return render_template('search.html')

def save_profile_picture(profile_picture):
    filename = secure_filename(profile_picture.filename)
    profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    
    if not user.is_authenticated:
        return redirect(url_for('login'))
    
    donated_items = Donation.query.filter_by(id=user.id).all() 
    requested_items = Request.query.filter_by(email=user.email).all()
    
    if request.method == 'POST':
        # Handle profile updates
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            user.profile_picture = save_profile_picture(profile_picture)
        user.name = request.form['name']
        user.email = request.form['email']
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        if new_password and new_password == confirm_password:
            user.set_password(new_password)
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user, donated_items=donated_items, requested_items=requested_items)


# Admin Dashboard Route
@app.route('/admin')
def admin_dashboard():
    pending_donations = Donation.query.filter_by(status='pending').all()
    pending_requests= Request.query.filter_by(status='pending').all()
    users = User.query.all()
    return render_template('admin_dashboard.html', pending_donations=pending_donations, pending_requests=pending_requests, users=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.name = request.form['name']
        user.last_name = request.form['last_name']
        user.email = request.form['email']
        db.session.commit()
        flash('User details updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/approve_donation/<int:donation_id>', methods=['POST'])
def admin_approve_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    donation.status = 'approved'
    # Update inventory
    inventory_item = Inventory.query.filter_by(name=donation.item_name).first()
    if inventory_item:
        inventory_item.qty += donation.quantity
    else:
        inventory_item = Inventory(name=donation.item_name, qty=donation.quantity, description=donation.description)
        db.session.add(inventory_item)
    db.session.commit()
    flash('Donation approved and inventory updated successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/mark_request_as_picked_up/<int:request_id>', methods=['POST'])
def mark_request_as_picked_up(request_id):
    request = Request.query.get_or_404(request_id)
    request.status = 'picked up'
    db.session.commit()
    flash('Request marked as picked up successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


def readFile():
    with open("static\csvFile.csv", 'r') as file:
    # Create a CSV reader object
        csv_reader = csv.reader(file)
        headers = next(csv_reader)
        data = [row for row in csv_reader]
        print("file read!")
        return data

def addInvetnory(data):
    for row in data:
        try:
            new_item = Inventory(
                name=row[0],
                description=row[1],
                qty=row[2],
                bank=row[3],
            )
            db.session.add(new_item)
            db.session.commit()
            print("Added item")
        except:
            db.session.rollback()
    print("yay it worked")

@app.route('/csv', methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        data = readFile()
        blah = addInvetnory(data)
    return render_template("csv.html")

if __name__ == "__main__":
    app.secret_key = "super_secret_key" 
    app.run(debug=True, port="1000")