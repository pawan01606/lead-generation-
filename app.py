from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
# SQLite database path compatible with Render and Windows
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'database.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------- Models -------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='user')

    def set_password(self, password):
        self.password = password  # For simplicity, store plaintext (use hashing in production)

    def check_password(self, password):
        return self.password == password

# Example Lead model
class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    branch_name = db.Column(db.String(100))
    customer_name = db.Column(db.String(100))
    contact_no = db.Column(db.String(50))
    loan_type = db.Column(db.String(50))
    loan_amount = db.Column(db.Float)
    interested = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(50), default='New')

# ------------------- Forms -------------------
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# ------------------- User Loader -------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------- Routes -------------------
@app.route('/')
@login_required
def home():
    leads = Lead.query.all()
    return render_template('index.html', leads=leads)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ------------------- Database Initialization -------------------
with app.app_context():
    db.create_all()

    # Create default admin if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('admin123')  # Change this password
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin created (admin / admin123)")

# ------------------- Run App -------------------
if __name__ == '__main__':
    app.run(debug=True)
