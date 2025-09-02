import sqlite3
from flask import Flask, render_template, session, request, redirect, url_for, flash, jsonify

app = Flask(__name__)
app.secret_key = "secret"
DB_PATH = "shruutech_ctf.db"

def get_challenges():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, hint, path_shown, points FROM challenges")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_challenge(challenge_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    flash("Registration is closed.", "warning")
    return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username")
        session["user_id"] = 1
        session["username"] = username
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["username"] = username
        return redirect(url_for("index"))

    return render_template("login.html")

@app.route("/submit_flag/<int:challenge_id>", methods=["POST"])
def submit_flag(challenge_id):
    if not session.get("user_id"):
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    submitted_flag = request.form.get("flag")

    challenge = get_challenge(challenge_id)
    if not challenge:
        flash("Challenge not found.", "danger")
        return redirect(url_for("index"))

    status = "Correct" if submitted_flag == challenge["flag"] else "Incorrect"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT 1 FROM submissions WHERE user_id=? AND challenge_id=? AND status='Correct'",
        (user_id, challenge_id)
    )
    already_solved = cursor.fetchone()

    if already_solved:
        flash("You have already solved this challenge.", "info")
    else:
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

    return redirect(url_for("index"))

@app.route("/profile")
def profile():
    if not session.get("user_id"):
        flash("Please login to view your profile.", "warning")
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT username, email, total_score FROM users WHERE id=?", (user_id,))
    user_row = cursor.fetchone()
    if not user_row:
        flash("User not found.", "danger")
        return redirect(url_for("index"))

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
        "username": user_row["username"],
        "email": user_row.get("email", "user@example.com"),
        "total_score": user_row["total_score"],
        "challenges_solved": challenges_solved,
        "submissions": submissions
    }

    return render_template("profile.html", user=user, current_page="profile")


@app.route("/leaderboard")
def leaderboard():
    if not session.get("user_id"):
        return "Please login to view leaderboard", 401
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT username, total_score FROM users ORDER BY total_score DESC LIMIT 3")
    top_players = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template("leaderboard.html", players=top_players, current_page="leaderboard")

@app.route("/leaderboard_data")
def leaderboard_data():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT username, total_score FROM users ORDER BY total_score DESC LIMIT 3")
    top_players = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(top_players)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
