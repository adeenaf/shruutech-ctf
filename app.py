import sqlite3
from flask import Flask, render_template, session, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, DataRequired, EqualTo

app = Flask(__name__)
app.secret_key = "supersecretkey"
csrf = CSRFProtect(app)

DB_PATH = "shruutech_ctf.db"

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 50)])
    password = PasswordField("Password", validators=[DataRequired(), Length(1, 128)])
    submit = SubmitField("Login")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired(), Length(1, 128)])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(6, 128)])
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo('new_password', message="Passwords must match")])
    submit = SubmitField("Change Password")

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 50)])
    password = PasswordField("Password", validators=[DataRequired(), Length(6, 128)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
    submit = SubmitField("Register")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_challenges():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, hint, path_shown, points FROM challenges")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_challenge(challenge_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, points, flag FROM challenges WHERE id=?", (challenge_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

@app.route("/")
def index():
    if not session.get("user_id"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    questions = get_challenges()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT challenge_id 
        FROM submissions
        WHERE user_id = ? AND status = 'Correct'
    """, (user_id,))
    solved_rows = cursor.fetchall()
    conn.close()
    solved_ids = [row["challenge_id"] for row in solved_rows]

    for q in questions:
        q['solved'] = q['id'] in solved_ids

    return render_template("index.html", questions=questions, current_page="index")

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    flash("Registration is closed.", "warning")
    return redirect(url_for("login"))
    """

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        password_hash = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()

        session["user_id"] = user_id
        session["username"] = username
        flash("Registration successful!", "success")
        return redirect(url_for("index"))

    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["username"] = username
        return redirect(url_for("index"))

    return render_template("login.html", form=form)

@app.route("/submit_flag/<int:challenge_id>", methods=["POST"])
def submit_flag(challenge_id):
    if not session.get("user_id"):
        return jsonify({"status": "error", "message": "Please login first"}), 401

    user_id = session.get("user_id")
    submitted_flag = request.form.get("flag")

    challenge = get_challenge(challenge_id)
    if not challenge:
        return jsonify({"status": "error", "message": "Challenge not found"}), 404

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM submissions WHERE user_id=? AND challenge_id=? AND status='Correct'",
        (user_id, challenge_id)
    )
    already_solved = cursor.fetchone()

    if already_solved:
        conn.close()
        return jsonify({"status": "already_solved"})

    status = "Correct" if submitted_flag == challenge["flag"] else "Incorrect"

    cursor.execute(
        "INSERT INTO submissions (user_id, challenge_id, flag, status) VALUES (?, ?, ?, ?)",
        (user_id, challenge_id, submitted_flag, status)
    )

    if status == "Correct":
        cursor.execute(
            "UPDATE users SET total_score = total_score + ? WHERE id = ?",
            (challenge["points"], user_id)
        )

    conn.commit()
    conn.close()

    return jsonify({"status": status})

@app.route("/profile")
def profile():
    if not session.get("user_id"):
        flash("Please login to view your profile.", "warning")
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username, email, total_score FROM users WHERE id=?", (user_id,))
    user_row = cursor.fetchone()
    if not user_row:
        flash("User not found.", "danger")
        return redirect(url_for("index"))

    # Use dict() to convert sqlite3.Row to a dict
    user_row_dict = dict(user_row)

    cursor.execute("""
        SELECT c.id, c.title 
        FROM challenges c
        JOIN submissions s ON s.challenge_id = c.id
        WHERE s.user_id = ? AND s.status = 'Correct'
        GROUP BY c.id
    """, (user_id,))
    challenges_solved = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT c.title as challenge_title, s.flag, s.status, s.timestamp
        FROM submissions s
        JOIN challenges c ON s.challenge_id = c.id
        WHERE s.user_id = ?
        ORDER BY s.timestamp DESC
    """, (user_id,))
    submissions = [dict(row) for row in cursor.fetchall()]

    conn.close()

    user = {
        "username": user_row_dict["username"],
        "email": user_row_dict.get("email") or "user@example.com",
        "total_score": user_row_dict["total_score"],
        "challenges_solved": challenges_solved,
        "submissions": submissions
    }

    return render_template("profile.html", user=user, current_page="profile")


@app.route("/leaderboard")
def leaderboard():
    if not session.get("user_id"):
        return "Please login to view leaderboard", 401
    return render_template("leaderboard.html", current_page="leaderboard")

@app.route("/leaderboard_data")
def leaderboard_data():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, total_score FROM users ORDER BY total_score DESC LIMIT 3")
    top_players = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(top_players)

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if not session.get("user_id"):
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    form = ChangePasswordForm()
    user_id = session.get("user_id")

    if form.validate_on_submit():
        current = form.current_password.data
        new = form.new_password.data

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id=?", (user_id,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user["password_hash"], current):
            flash("Current password is incorrect.", "danger")
        else:
            new_hash = generate_password_hash(new)
            cursor.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user_id))
            conn.commit()
            flash("Password changed successfully.", "success")
        conn.close()
        return redirect(url_for("profile"))

    return render_template("change_password.html", form=form, current_page="profile")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
