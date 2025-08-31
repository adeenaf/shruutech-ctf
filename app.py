from flask import Flask, render_template, session, request, redirect, url_for, flash
from operator import itemgetter

app = Flask(__name__)
app.secret_key = "secret"

mock_players = [
    {"username": "Alice", "score": 5},
    {"username": "Bob", "score": 3},
    {"username": "Charlie", "score": 4},
]

@app.route("/")
def index():
    questions = [
        {"id": 1, "title": "Challenge 1", "description": "Find the flag.", "feedback": None},
        {"id": 2, "title": "Challenge 2", "description": "Another challenge.", "feedback": None},
    ]
    return render_template("index.html", questions=questions)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        session["user_id"] = 1
        session["username"] = username
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        session["user_id"] = 1
        session["username"] = username
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/leaderboard")
def leaderboard():
    if not session.get("user_id"):
        return "Please login to view leaderboard", 401
    top_players = sorted(mock_players, key=itemgetter("score"), reverse=True)[:3]

    return render_template("leaderboard.html", players=top_players)

if __name__ == "__main__":
    app.run(debug=True)
