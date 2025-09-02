import sqlite3
from flask import Flask, render_template, session, request, redirect, url_for, flash
from operator import itemgetter

app = Flask(__name__)
app.secret_key = "secret"

DB_PATH = "shruutech_ctf.db"

mock_players = [
    {"username": "Alice", "score": 5},
    {"username": "Bob", "score": 3},
    {"username": "Charlie", "score": 4},
]

def get_challenges():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, hint, path_shown, points FROM challenges")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_flag(challenge_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT flag FROM challenges WHERE id=?", (challenge_id,))
    flag = cursor.fetchone()[0]
    conn.close()
    return flag

@app.route("/")
def index():
    questions = get_challenges()
    solved = session.get("solved_challenges", [])
    for q in questions:
        q['solved'] = q['id'] in solved
    return render_template("index.html", questions=questions, current_page="index")

@app.route("/register", methods=["GET", "POST"])
def register():
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
        session["user_id"] = 1
        session["username"] = username
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/submit_flag/<int:question_id>", methods=["POST"])
def submit_flag(challenge_id):
    submitted_flag = request.form.get("flag")
    correct_flag = get_flag(challenge_id)

    if submitted_flag == correct_flag:
        flash("Correct Answer!", "success")
        solved = session.get("solved_challenges", [])
        if challenge_id not in solved:
            solved.append(challenge_id)
            session["solved_challenges"] = solved
        else:
            flash("Incorrect Answer.", "danger")

    return redirect(url_for("index"))

@app.route("/profile")
def profile():
    if not session.get("user_id"):
        flash("Please login to view your profile.", "warning")
        return redirect(url_for("login"))

    # Mock user data
    user = {
        "username": session.get("username"),
        "email": "user@example.com",
        "total_score": 5,
        "challenges_solved": [
            {"title": "Challenge 1"},
            {"title": "Challenge 2"}
        ],
        "submissions": [
            {"challenge_title": "Challenge 1", "flag": "flag{123}", "status": "Correct"},
            {"challenge_title": "Challenge 2", "flag": "flag{abc}", "status": "Incorrect"}
        ]
    }

    return render_template("profile.html", user=user, current_page="profile")

@app.route("/leaderboard")
def leaderboard():
    if not session.get("user_id"):
        return "Please login to view leaderboard", 401
    top_players = sorted(mock_players, key=itemgetter("score"), reverse=True)[:3]

    return render_template("leaderboard.html", players=top_players, current_page="leaderboard")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
