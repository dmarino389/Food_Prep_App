from flask import render_template, request, flash, redirect, url_for
import jinja2
from app import app, db
from app.forms import RegistrationForm, LoginForm
from app.models import User
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
# -----------------------------------------------------------------

@app.route('/')
def home():
  return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Username already exists. Please choose a different username.', 'danger')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            user = User(username=form.username.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Error during registration: {str(e)}")
            flash('An error occurred during registration. Please try again later.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)
# -----------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=False)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)


from sqlalchemy.exc import IntegrityError
# -----------------------------------------------------------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
    # -----------------------------------------------------------------