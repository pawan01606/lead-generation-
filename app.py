import os
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, DateField, IntegerField, SelectField
from wtforms.validators import DataRequired, Length

# -------------------------------
# App Configuration
# -------------------------------
app = Flask(__name__)

# SECRET_KEY from environment or fallback
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

# SQLite path for Render or local
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'database.db')

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',        # Postgres on Render
    f"sqlite:///{db_path}" # fallback SQLite
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# -------------------------------
# Database
# -------------------------------
db = SQLAlchemy(app)

# -------------------------------
# Login Manager
# -------------------------------
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# -------------------------------
# Models
# -------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(150))
    role = db.Column(db.String(10))  # admin or user

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    branch_name = db.Column(db.String(150))
    customer_name = db.Column(db.String(150))
    contact_no = db.Column(db.String(50))
    date_of_lead = db.Column(db.String(50))
    monthly_income = db.Column(db.Integer)
    lead_source = db.Column(db.String(150))
    purpose = db.Column(db.String(150))
    loan_amount = db.Column(db.Integer)
    interested = db.Column(db.String(10))
    follow_up_date = db.Column(db.String(50))
    current_status = db.Column(db.String(50))

# -------------------------------
# Forms
# -------------------------------
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# -------------------------------
# User Loader
# -------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------
# Routes
# -------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials")
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    leads = Lead.query.all()
    return render_template('dashboard.html', leads=leads, user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# -------------------------------
# Before First Request
# -------------------------------
@app.before_first_request
def create_admin_and_db():
    # Create instance folder if not exists
    if not os.path.exists(os.path.join(basedir, 'instance')):
        os.makedirs(os.path.join(basedir, 'instance'))

    db.create_all()

    # Create default admin if not exists
    if not User.query.filter_by(username='admin').first():
        u = User(username='admin', role='admin')
        u.set_password('admin123')
        db.session.add(u)
        db.session.commit()
        print("✅ Default admin user created (admin / admin123)")

# -------------------------------
# Run App
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
