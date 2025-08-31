from flask import Flask, render_template, session, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "secret"

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

if __name__ == "__main__":
    app.run(debug=True)
