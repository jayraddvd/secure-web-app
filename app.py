import os
import sqlite3

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-key-change-before-production",
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Change to True when using HTTPS in production
app.config["SESSION_COOKIE_SECURE"] = False

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
)


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = sqlite3.connect("users.db")
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,),
        )

        user = cursor.fetchone()
        connection.close()

        if user and check_password_hash(user[2], password):
            session.clear()
            session["user_id"] = user[0]
            session["username"] = user[1]

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "error")
            return render_template("register.html")

        if len(username) > 30:
            flash("Username cannot contain more than 30 characters.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)

        connection = sqlite3.connect("users.db")
        cursor = connection.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password),
            )

            connection.commit()

        except sqlite3.IntegrityError:
            flash("That username already exists.", "error")
            return render_template("register.html")

        finally:
            connection.close()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to view the dashboard.", "error")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"],
    )


@app.route("/logout")
def logout():
    session.clear()

    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.errorhandler(429)
def rate_limit_exceeded(error):
    return render_template("429.html"), 429


if __name__ == "__main__":
    app.run(debug=True)