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
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///library.db"
db = SQLAlchemy(app)

class Inventory(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    description = db.Column(db.String)
    qty = db.Column(db.Interger)
    bank = db.Column(db.String)

    def __repr__(self):
        db.create.all()


with app.app.context():
    db.create_all()

def parse_csv_data(csv_file):
    text_data = csv_file.read().decode("utf-8")
    reader = csv.reader(io.StringIO(text_data))
    headers = next(reader)
    data = [row for row in reader]
    return data


# Function to add CSV data to the database
def add_csv_data_to_database(csv_data):
    for item in csv_data:
        try:
            new_inventory = Inventory(
                title=item[0],
                description=item[1],
                qty=item[2],
                bank=item[3],
            )
            db.session.add(new_inventory)
            db.session.commit()
        except:
            db.session.rollback()



app.route('/csv', methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        csv_file = request.files["csv_file"]
        csv_data = parse_csv_data(csv_file)
        add_csv_data_to_database(csv_data)
        flash("Books added from CSV successfully", "success")
        return render_template(
            "uploadbook.html",
            msg="The books have been added into our inventory!",
        )
    return render_template("uploadbook.html")

