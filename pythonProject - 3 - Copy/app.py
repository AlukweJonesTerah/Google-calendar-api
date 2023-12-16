# app.py
# from app_factory import create_app
import logging

from flask import Flask, render_template, url_for, flash, jsonify, request, redirect, session, make_response

# database imports
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import SQLAlchemyError

# Login imports
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# session imports
from flask_session import Session
from config import Config
from loggings import configure_logging

# form imports
# form imports  forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp, Email, DataRequired
import re
# from Models import User
from email_validator import validate_email, EmailNotValidError
from flask_wtf import CSRFProtect

# ecryption
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_talisman import Talisman

app = Flask(__name__, static_folder='static')
app.config.from_object(Config)
db = SQLAlchemy(app)

# Configure logging
configure_logging(app, config=Config)
# csrf = CSRFProtect(app)
tailsman = Talisman(app)
logging.basicConfig(level=logging.INFO)

# Initialize Flask extensions

migrate = Migrate(app, db)
Session(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.init_app(app)


@app.errorhandler(SQLAlchemyError)
def handle_database_error(e):
    # Log error
    app.logger.error(f'Database error: {str(e)}')
    # user-friendly response
    return jsonify({'error': 'A database error occurred'}), 500


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    google_calendar_token = db.Column(db.String(200))  # store google calendar api token
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def set_google_calendar_token(self, token):
        self.google_calendar_token = token
        db.session.commit()

    def get_google_calendar_token(self):
        return self.google_calendar_token
# db.init_app(app)
with app.app_context():
    db.create_all()


# form
class RegistrationForm(FlaskForm):
    first_name = StringField(validators=[InputRequired(), Length(max=30),
                                         Regexp('^[a-zA-Z-]+$',
                                                message='First name can only contain letters and hyphens')],
                             render_kw={"placeholder": "Fist Name"})
    last_name = StringField(validators=[InputRequired(), Length(max=30),
                                        Regexp('^[a-zA-Z-]+$',
                                               message='Last name can only contain letters and hyphens')],
                            render_kw={"placeholder": "Last Name"})
    phone_number = StringField(
        validators=[InputRequired(), Regexp('^[0-9]+$', message='Phone number can only contain numbers'),
                    Length(min=10, max=15)],
        render_kw={"placeholder": "Phone Number"})
    email = StringField(validators=[InputRequired(), Email(), Length(max=50)],
                        render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), Length(min=4, max=20),
                                       Regexp('^[a-zA-Z0-9_.-]+$',
                                              message="Username can only contain letters. numbers, underscores, dots, and hyphens")],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20),
                                         Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()-_+=]).*$',
                                                message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character")],
                             render_kw={"placeholder": "password"})

    submit = SubmitField('Register')

    def validate_field_without_whitespace(self, field):
        if field.data.strip() != field.data:
            raise ValidationError('Field cannot have leading or trialing whitespaces.')
        try:
            email = validate_email(field.data).email
        except EmailNotValidError as e:
            raise ValidationError(f'Invalid email {e}')

    def validate_first_name(self, first_name):
        if not re.match("^[a-zA-Z-]+$", first_name.data):
            raise ValidationError('First name can only contain letters and hyphens.')
        if '  ' in first_name.data:
            raise ValidationError('First name cannot contain consecutive spaces.')

        if not first_name.data.isalpha():
            raise ValidationError('First name can only contain letters.')

    def validate_last_name(self, last_name):
        if not re.match("^[a-zA-Z-]+$", last_name.data):
            raise ValidationError('Last name can only contain letters and hyphens.')

        if '  ' in last_name.data:
            raise ValidationError('Last name cannot contain consecutive spaces.')

        if not last_name.data.isalpha():
            raise ValidationError('Last name can only contain letters.')

    def validate_phone_number(self, phone_number):
        if not re.match("^[0-9]+$", phone_number.data):
            raise ValidationError('Phone number can only contain numbers.')

            # Check for a valid phone number length (adjust as needed)
        min_length = 10
        max_length = 15
        if not min_length <= len(phone_number.data) <= max_length:
            raise ValidationError(f'Phone number must be between {min_length} and {max_length} digits long.')
        # Check for a valid country code

        # valid_country_codes = ['+1', '+44', '+81', '+254', '+255']  # Add more country codes as needed
        # if not any(phone_number.data.startswith(code) for code in valid_country_codes):
        #     raise ValidationError('Invalid country code.')

        # Ensure the phone number doesn't start with a leading zero
        if phone_number.data.startswith('0'):
            raise ValidationError('Phone number cannot start with a leading zero.')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError('That email address is already registered. Please use a different one.')
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern, email.data):
            raise ValidationError('Invalid email format.')

        allowed_domains = ['example.com', 'gmail.com', 'kabarak.ac.ke']
        if email.data.split('@')[1] not in allowed_domains:
            raise ValidationError('Invalid email domain.')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username is already taken. Please choose a different one.')
        if not username.data[0].isalpha():
            raise ValidationError('Username must start with a letter.')
        if not username.data.isalnum():
            raise ValidationError('Username can only contain letters and numbers.')

    def validate_password(self, password):
        if not any(char.isupper() for char in password.data):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not any(char.islower() for char in password.data):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not any(char.isdigit() for char in password.data):
            raise ValidationError('Password must contain at least one digit.')
        special_characters = "!@#$%^&*()-_+=<>,.?/:;{}[]|"
        if not any(char in special_characters for char in password.data):
            raise ValidationError('Password must contain at least one special character (!@#$%^&*()-_+=<>,.?/:;{}[]|).')
        if self.username.data.lower() in password.data.lower():
            raise ValidationError('Password cannot contain the username.')
        consecutive_char = {''.join(chr(ord(c) + i) for i in range(3)) for c in 'abcdefghijklmnopqrstuvwxyz'} | {
            ''.join(str(i) for i in range(3))}
        if any(consecutive in password.data.lower() for consecutive in consecutive_char):
            raise ValidationError('Password cannot contain consecutive characters (e.g., "abc", "123").')
        if any(password.data.count(char * 2) for char in password.data):
            raise ValidationError('Password cannot contain repeated characters (e.g., "aa", "111").')
        min_length = 8
        if len(password.data) < min_length:
            raise ValidationError(f'Password must be at least {min_length} characters long.')
        max_length = 20
        if len(password.data) > max_length:
            raise ValidationError(f'Password must be at most {max_length} characters long.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


#
#
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegistrationForm()
#
#     if form.validate_on_submit():
#         hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
#         new_user = User(first_name=form.first_name.data, last_name=form.last_name.data,
#                         phone_number=form.phone_number.data, email=form.email.data, username=form.username.data,
#                         password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#
#         return jsonify({'message': 'Registration successful'}), 200
#
#     # Form is not valid
#     errors = {'errors': {field.name: field.errors for field in form}}
#     return jsonify(errors), 400


@app.route('/setcookies')
def setcookies():
    resp = make_response('Setting the cookies')
    resp.set_cookie('GFG', 'ComputerSciencePortal')
    return resp

@app.route('/getcookie')
def getcookie():
    GFG = request.cookies.get('GFG')
    return 'GFG is a'+GFG

@app.route('/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(first_name=form.first_name.data, last_name=form.last_name.data,
                        phone_number=form.phone_number.data, email=form.email.data, username=form.username.data,
                        password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account was created successfully', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            logging.error(f'Error we could not save you deta ils!: {str(e)}', 'danger')
            flash(f'Error we could not save you details!: {str(e)}', 'danger')

    return render_template('register.html', form=form)


# field validation section
@app.route('/validation/<field>', methods=['POST'])
def validation_field(field):
    data = request.get_json()
    value_to_validate = data.get(field, '')

    # Perform validation logic here
    validation_result = validate_field_logic(field, value_to_validate)
    return jsonify({'message': validation_result})


def validate_field_logic(field, value):
    # Perform field-specific validations logic here
    if field == 'first_name':
        min_length, max_length = 2, 50
        if not value:
            return 'First name is required.'
        elif not value.isalpha():
            return 'First name should contain only alphabetic characters'
        elif not (min_length <= len(value) <= max_length):
            return f'First name should be between {min_length} and {max_length} characters'
        elif not re.match("^[a-zA-Z-]+$", value):
            return 'First name can only contain letters and hyphens.'
        elif '  ' in value:
            return 'First name cannot contain consecutive spaces.'
        else:
            return 'First name valid'
    elif field == 'last_name':
        min_length, max_length = 2, 50
        if not value:
            return 'Last name is required.'
        elif not value.isalpha():
            return 'Last name should contain only alphabetic characters'
        elif not (min_length <= len(value) <= max_length):
            return f'Last name should be between {min_length} and {max_length} characters'
        elif not re.match("^[a-zA-Z-]+$", value):
            return 'Last name can only contain letters and hyphens.'
        elif '  ' in value:
            return 'Last name cannot contain consecutive spaces.'
        else:
            return 'Last name valid'
    elif field == 'phone_number':
        min_length, max_length = 10, 15
        if not value:
            return 'Phone number is required.'
        elif not re.match("^[0-9]+$", value):
            return 'Phone number can only contain numbers.'
        elif not min_length <= len(value) <= max_length:
            return f'Phone number must be between {min_length} and {max_length} digits long.'
        elif value.startswith('0'):
            return 'Phone number cannot start with a leading zero.'
        else:
            return 'Phone is valid'
    elif field == 'email':
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        allowed_domains = ['example.com', 'gmail.com', 'kabarak.ac.ke']
        if not value:
            return 'Email is required.'
        elif User.query.filter_by(email=value).first():
            return 'That email is already registered.'
        elif not re.match(email_pattern, value):
            return 'Invalid email format.'
        elif value.split('@')[1] not in allowed_domains:
            return 'Invalid email domain.'
        else:
            return 'Email is valid.'
    elif field == 'username':
        if not value:
            return 'Username is required.'
        elif User.query.filter_by(username=value).first():
            return 'Username is already taken.'
        elif not value[0].isalpha():
            return 'Username must start with a letter.'
        elif not value.isalnum():
            return 'Username can only contain letters and numbers.'
        else:
            return 'Username is valid.'
    elif field == 'password':
        special_characters = "!@#$%^&*()-_+=<>,.?/:;{}[]|"
        consecutive_char = {''.join(chr(ord(c) + i) for i in range(3)) for c in 'abcdefghijklmnopqrstuvwxyz'} | {
            ''.join(str(i) for i in range(3))}
        min_length, max_length = 8, 20
        if not value:
            return 'Password is required.'
        elif not any(char.isupper() for char in value):
            return 'Password must contain at least one uppercase letter.'
        elif not any(char.islower() for char in value):
            return 'Password must contain at least one lowercase letter.'
        elif not any(char.isdigit() for char in value):
            return 'Password must contain at least one digit.'
        elif not any(char in special_characters for char in value):
            return 'Password must contain at least one special character (!@#$%^&*()-_+=<>,.?/:;{}[]|).'
        elif value.lower() in value.lower():
            return 'Password cannot contain the username.'
        elif any(consecutive in value.lower() for consecutive in consecutive_char):
            return 'Password cannot contain consecutive characters (e.g., "abc", "123").'
        elif any(value.count(char * 2) for char in value):
            return 'Password cannot contain repeated characters (e.g., "aa", "111").'
        elif len(value) < min_length:
            return f'Password must be at least {min_length} characters long.'
        elif len(value) > max_length:
            return f'Password must be at most {max_length} characters long.'
        else:
            return 'Password valid.'
    else:
        return 'Validation successful.'


@app.route('/login', methods=['GET'])
def login_page():
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/login', methods=['POST'])
def login():
    form = LoginForm(request.form)

    try:
        if request.method == 'POST':
            if form.validate_on_submit() or form.validate():
                user = User.query.filter_by(username=form.username.data).first()

                if user and bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    # Todo: consider removing session line
                    session['username'] = form.username.data

                    # Check for AJAX requests, return response
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'message': 'Login was successful', 'redirect': url_for('index')})

                    flash(f'Login was successful. Welcome, {current_user.username}!', 'success')

                    app.logger.info(f'Successful login: {current_user.username}')

                    return redirect(url_for('register'))
                else:
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'message': 'Invalid username or password'})
                    flash('Invalid username or password. Please try again.', 'danger')
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'message': 'Form validation failed'})
        flash('Form validation failed. Please try again.', 'danger')

    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'message': 'An error occurred during login.'})
        app.logger.error(f'Error during login: {e}')
        flash('An error occurred during login. Please try again.', 'danger')
    return render_template('login.html', form=form)

def get_user_email(user=None):
    if isinstance(user, int):
        email = User.query.get(user)
    email = getattr(user, 'email', None)
    if email:
        return email
    else:
        logging.warning(f"Failed to retrieve email for user: {user}")
    return None

@app.before_request
def before_request():
    if 'user_id' in session:
        session.permanent = True

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    if current_user.is_authenticated:
        db.session.commit()
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

@app.route('/leave-site', methods=['POST'])
def leave_site():
    if current_user.is_authenticated:
        current_user.last_activity = datetime.utcnow()
        db.session.commit()
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': 'User not authenticated'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    if request.is_json:
        return jsonify({'message': 'Logout successful', 'redirect': url_for('login')}), 200
    else:
        flash('You have logged out', 'info')
        return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
