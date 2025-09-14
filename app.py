from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# ------------------------
# Flask App Config
# ------------------------
app = Flask(__name__)

# SECRET_KEY for Render (env) or fallback
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

# DATABASE_URL for Render Postgres, fallback sqlite
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'sqlite:///database.db'
)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ------------------------
# Database Models
# ------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin or user
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Basic info
    branch_name = db.Column(db.String(100))
    customer_name = db.Column(db.String(100))
    contact_no = db.Column(db.String(20))
    date_of_lead = db.Column(db.String(20))
    monthly_income = db.Column(db.String(50))

    # Loan specific
    lead_source = db.Column(db.String(50))
    purpose_of_loan = db.Column(db.String(200))
    loan_amount = db.Column(db.Float)
    interest = db.Column(db.String(10))

    # Follow up
    follow_up_date = db.Column(db.String(20))
    current_status = db.Column(db.String(100))

# ------------------------
# User loader
# ------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------
# Initialize DB + default admin
# ------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        u = User(username="admin", role="admin")
        u.set_password("admin123")
        db.session.add(u)
        db.session.commit()
        print("✅ Default admin user created (admin / admin123)")

# ------------------------
# Routes
# ------------------------
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    leads = Lead.query.all()
    return render_template("dashboard.html", leads=leads, role=current_user.role)

@app.route("/add_lead", methods=["GET", "POST"])
@login_required
def add_lead():
    if current_user.role != "admin":
        flash("Only admin can add leads.")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        lead = Lead(
            branch_name=request.form.get("branch_name"),
            customer_name=request.form.get("customer_name"),
            contact_no=request.form.get("contact_no"),
            date_of_lead=request.form.get("date_of_lead"),
            monthly_income=request.form.get("monthly_income"),
            lead_source=request.form.get("lead_source"),
            purpose_of_loan=request.form.get("purpose_of_loan"),
            loan_amount=request.form.get("loan_amount"),
            interest=request.form.get("interest"),
        )
        db.session.add(lead)
        db.session.commit()
        flash("Lead added successfully!")
        return redirect(url_for("dashboard"))

    return render_template("add_lead.html")

@app.route("/followup/<int:lead_id>", methods=["GET", "POST"])
@login_required
def followup(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    if request.method == "POST":
        # Both admin and user can update follow-up
        lead.follow_up_date = request.form.get("follow_up_date")
        lead.current_status = request.form.get("current_status")
        db.session.commit()
        flash("Follow-up updated successfully!")
        return redirect(url_for("dashboard"))

    return render_template("followup.html", lead=lead)

# ------------------------
# Run app (local dev only)
# ------------------------
if __name__ == "__main__":
    app.run(debug=True)
