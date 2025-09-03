import os
import sqlite3
from dotenv import load_dotenv
from flask import Flask, render_template, session, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, DataRequired, EqualTo, Email

app = Flask(__name__)
load_dotenv()
app.secret_key = os.environ.get("SECRET_KEY")
csrf = CSRFProtect(app)
DB_PATH = "shruutech_ctf.db"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 50)])
    password = PasswordField("Password", validators=[DataRequired(), Length(1, 128)])
    submit = SubmitField("Login")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired(), Length(1, 128)])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(8, 128)])
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo('new_password', message="Passwords must match")])
    submit = SubmitField("Change Password")

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 50)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(1, 100)])
    password = PasswordField("Password", validators=[DataRequired(), Length(8, 128)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
    submit = SubmitField("Register")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def query_db(query, args=(), one=False, commit=False):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    if commit:
        conn.commit()
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv


def get_challenges():
    return [dict(r) for r in query_db("SELECT id, title, hint, path_shown, points FROM challenges")]

def get_challenge(challenge_id):
    row = query_db("SELECT id, title, points, flag FROM challenges WHERE id=?", (challenge_id,), one=True)
    return dict(row) if row else None

def login_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        user = query_db("SELECT is_admin FROM users WHERE id=?", (session['user_id'],), one=True)
        if not user or user["is_admin"] != 1:
            flash("You are not authorized to view this page.", "danger")
            return redirect(url_for("index"))
        return func(*args, **kwargs)
    return wrapper

@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    challenges = get_challenges()
    solved_ids = [r["challenge_id"] for r in query_db(
        "SELECT challenge_id FROM submissions WHERE user_id=? AND status='Correct'", (user_id,)
    )]
    for c in challenges:
        c['solved'] = c['id'] in solved_ids
    return render_template("index.html", questions=challenges, current_page="index")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if query_db("SELECT 1 FROM users WHERE username=?", (form.username.data,), one=True):
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))
        try:
            query_db(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (form.username.data, form.email.data, generate_password_hash(form.password.data, method="pbkdf2:sha256")),
                commit=True)
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
            return redirect(url_for("register"))
        
        user_id = query_db("SELECT id FROM users WHERE username=?", (form.username.data,), one=True)["id"]
        session["user_id"] = user_id
        session["username"] = form.username.data
        flash("Registration successful!", "success")
        return redirect(url_for("index"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = query_db("SELECT id, password_hash FROM users WHERE username=?", (form.username.data,), one=True)
        if not user or not check_password_hash(user["password_hash"], form.password.data):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))
        session["user_id"] = user["id"]
        session["username"] = form.username.data

        return redirect(url_for("index"))
    return render_template("login.html", form=form)

@app.route("/submit_flag/<int:challenge_id>", methods=["POST"])
@login_required
def submit_flag(challenge_id):
    user_id = session["user_id"]
    flag = request.form.get("flag")
    challenge = get_challenge(challenge_id)
    if not challenge:
        return jsonify({"status": "error", "message": "Challenge not found"}), 404
    if query_db("SELECT 1 FROM submissions WHERE user_id=? AND challenge_id=? AND status='Correct'", (user_id, challenge_id), one=True):
        return jsonify({"status": "already_solved"})
    status = "Correct" if flag == challenge["flag"] else "Incorrect"
    query_db(
        "INSERT INTO submissions (user_id, challenge_id, flag, status) VALUES (?, ?, ?, ?)",
        (user_id, challenge_id, flag, status),
        commit=True
    )
    if status == "Correct":
        query_db("UPDATE users SET total_score = total_score + ? WHERE id=?", (challenge["points"], user_id), commit=True)
    return jsonify({"status": status})

@app.route("/profile")
@login_required
def profile():
    user_id = session["user_id"]
    user_row = query_db("SELECT username, email, total_score FROM users WHERE id=?", (user_id,), one=True)
    if not user_row:
        flash("User not found.", "danger")
        return redirect(url_for("index"))
    challenges_solved = [dict(r) for r in query_db(
        "SELECT c.id, c.title FROM challenges c JOIN submissions s ON s.challenge_id=c.id WHERE s.user_id=? AND s.status='Correct' GROUP BY c.id", (user_id,)
    )]
    submissions = [dict(r) for r in query_db(
        "SELECT c.title as challenge_title, s.flag, s.status, s.timestamp FROM submissions s JOIN challenges c ON s.challenge_id=c.id WHERE s.user_id=? ORDER BY s.timestamp DESC", (user_id,)
    )]
    user = {**dict(user_row), "challenges_solved": challenges_solved, "submissions": submissions}
    return render_template("profile.html", user=user, current_page="profile")

@app.route("/leaderboard")
@login_required
def leaderboard():
    players = [dict(r) for r in query_db("SELECT username, total_score FROM users ORDER BY total_score DESC LIMIT 3")]
    return render_template("leaderboard.html", players=players, current_page="leaderboard")

@app.route("/leaderboard_data")
@login_required
def leaderboard_data():
    top_players = [dict(r) for r in query_db("SELECT username, total_score FROM users ORDER BY total_score DESC LIMIT 3")]
    return jsonify(top_players)

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    user_id = session["user_id"]
    if form.validate_on_submit():
        user = query_db("SELECT password_hash FROM users WHERE id=?", (user_id,), one=True)
        if not user or not check_password_hash(user["password_hash"], form.current_password.data):
            flash("Current password is incorrect.", "danger")
        else:
            query_db("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(form.new_password.data, method="pbkdf2:sha256")
, user_id), commit=True)
            flash("Password changed successfully.", "success")
        return redirect(url_for("profile"))
    return render_template("change_password.html", form=form, current_page="profile")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.route("/admin")
@login_required
def admin_panel():
    # Only allow admins
    user_id = session["user_id"]
    user = query_db("SELECT is_admin FROM users WHERE id=?", (user_id,), one=True)
    if not user or user["is_admin"] != 1:
        flash("Access denied.", "danger")
        return redirect(url_for("index"))

    users = [dict(u) for u in query_db("SELECT id, username, email, total_score FROM users")]
    challenges = [dict(c) for c in query_db("SELECT id, title, points FROM challenges")]

    # For each user, get solved challenges
    user_solved = {}
    for u in users:
        solved = [r["challenge_id"] for r in query_db(
            "SELECT challenge_id FROM submissions WHERE user_id=? AND status='Correct'", (u["id"],)
        )]
        user_solved[u["id"]] = solved

    return render_template("admin.html", users=users, challenges=challenges, user_solved=user_solved)

if __name__ == "__main__":
    app.run()
