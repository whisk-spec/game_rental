from flask import Flask, render_template, request, redirect, url_for, session, flash
from models import db, User, Game, Wishlist
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length, Regexp, Email
import bleach
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///game_rental.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
db.init_app(app)

# Initialize Flask-Limiter
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# WTForms for Registration and Login
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=12, message="Username must be between 3 and 12 characters."),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, and underscores.")
    ])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, max=12, message="Password must be between 6 and 12 characters.")
    ])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=12)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=12)])

# Login Route
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = bleach.clean(form.username.data)
        password = bleach.clean(form.password.data)
        user = User.query.filter_by(username=username).first()

        if user is None:
            flash("User not found. Please check your username.", 'danger')
            return render_template('login.html', form=form)

        if not check_password_hash(user.password_hash, password):
            flash("Incorrect password. Please try again.", 'danger')
            return render_template('login.html', form=form)

        # Successful login
        session['user_id'] = user.id
        flash('Login successful!', 'success')
        return redirect(url_for('index'))

    # Form validation errors
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field.capitalize()}: {error}", 'danger')

    return render_template('login.html', form=form)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = bleach.clean(form.username.data)
        email = bleach.clean(form.email.data)
        password = bleach.clean(form.password.data)

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.email == email:
                flash("This email is already registered. Please use a different email.", 'danger')
            else:
                flash("This username is already taken. Please choose a different username.", 'danger')
            return render_template('register.html', form=form)

        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    # Form validation errors
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field.capitalize()}: {error}", 'danger')

    return render_template('register.html', form=form)

# Browse Games Route
@app.route('/browse')
def browse():
    games = Game.query.all()
    return render_template('browse.html', games=games)

# Wish List Route
@app.route('/wish_list')
def wish_list():
    if 'user_id' not in session:
        flash('Please log in to view your wishlist.', 'warning')
        return redirect(url_for('login'))
    user_id = session['user_id']
    wishlist_items = Wishlist.query.filter_by(user_id=user_id).all()
    return render_template('wish_list.html', wishlist_items=wishlist_items)

# Add to Wishlist Route
@app.route('/add_to_wishlist/<int:game_id>', methods=['POST'])
def add_to_wishlist(game_id):
    if 'user_id' not in session:
        flash("Please log in to add games to your wishlist.", 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    existing_item = Wishlist.query.filter_by(user_id=user_id, game_id=game_id).first()

    if not existing_item:
        wishlist_item = Wishlist(user_id=user_id, game_id=game_id)
        db.session.add(wishlist_item)
        db.session.commit()
        flash("Game added to your wishlist!", 'success')
    else:
        flash("This game is already in your wishlist.", 'info')

    return redirect(url_for('browse'))

# Home Page Route
@app.route('/')
def index():
    games = Game.query.all()
    return render_template('index.html', games=games)

# Initialize Database
@app.before_first_request
def setup():
    db.create_all()

# Run the Application
if __name__ == '__main__':
    app.run(debug=False)

