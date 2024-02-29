from flask import render_template, request, flash, redirect, url_for
import jinja2
from app import app, db
from app.forms import RegistrationForm, LoginForm
from app.models import User
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash


@app.route('/')
def index():
  return render_template('index.html')