#imports
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import os, io
from werkzeug.utils import secure_filename
import csv
from sqlalchemy import desc, asc

app = Flask(__name__)

#routes
@app.route('/')
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.secret_key = "super_secret_key" 
    app.run(debug=True, port="8000")

app.route('/inventory')
def inventory():
    #plan for this route
    #when person requests food from a card, post and then add information to a list, then go back to get to display list
    #edit/get for cart is the thing where submit buttons have different names
    #seperate route/function for commiting things to DB
    pass