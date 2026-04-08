from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Dict

from flask import Flask, render_template, request, abort, url_for, redirect, session
from flask import jsonify
from pathlib import Path
import json
import validation
import encryption
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = b'1234567890123456'

BASE_DIR = Path(__file__).resolve().parent
USERS_PATH = BASE_DIR / "data" / "users.json"
PLANTS_PATH = BASE_DIR / "data" / "plants.json"
COMMENTS_PATH = BASE_DIR / "data" / "comments.json"


def _user_with_defaults(u: dict) -> dict:
    u = dict(u)
    u.setdefault("role", "user")      
    u.setdefault("status", "active")  
    u.setdefault("locked_until", "") 
    return u

def get_current_user() -> Optional[dict]:
    email = session.get("user_email")
    if not email:
        return None
    return find_user_by_email(email)

def _parse_date(date_str: str) -> Optional[datetime]:
    """Parsea fecha estilo YYYY-MM-DD. Devuelve None si inválida."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None


def _safe_int(value: str, default: int = 1, min_v: int = 1, max_v: int = 10) -> int:
    """Validación simple de enteros para inputs (cantidad, etc.)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_v, min(max_v, n))

def load_users() -> list[dict]:
    if not USERS_PATH.exists():
        USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERS_PATH.write_text("[]", encoding="utf-8")
    return json.loads(USERS_PATH.read_text(encoding="utf-8"))

def save_users(users: list[dict]) -> None:
    USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")


def find_user_by_email(email: str) -> Optional[dict]:
    users = load_users()
    email_norm = (email or "").strip().lower()
    for u in users:
        if (u.get("email", "") or "").strip().lower() == email_norm:
            return u
    return None


def user_exists(email: str) -> bool:
    return find_user_by_email(email) is not None

def require_login() -> None:
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    

def require_admin():
    login_check = require_login()
    if login_check:  
        return login_check
    user = get_current_user()
    if user["role"] != "admin":
        return render_template(
            "error.html",
            error=403,
            message="Forbidden content"
        ), 403
    return None 

    
# -----------------------------
# Rutas
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        registered = request.args.get("registered")
        msg = "Account created successfully. Please sign in." if registered == "1" else None
        return render_template("login.html", info_message=msg)
    
    email = request.form.get("email", "")
    password = request.form.get("password", "")

    field_errors = {}

    if not email.strip():
        field_errors["email"] = "Email is required."
    else:
        email, err = validation.validate_billing_email(email)
        if err: 
            field_errors["email"] = "Email format not valid"
    if not password.strip():
        field_errors["password"] = "Password is required."
    
    if field_errors:
        return render_template(
            "login.html",
            error="Please fix the highlighted fields.",
            field_errors=field_errors,
            form={"email": email},
        ), 400

    user = find_user_by_email(email)
    if not user or not encryption.verify_password(password, user.get("password")):
        update_block()
        return render_template(
            "login.html",
            error="Invalid credentials.",
            field_errors={"email": " ", "password": " "},
            form={"email": email},
        ), 401
    delete_block()
    session["user_email"] = (user.get("email") or "").strip().lower()
    session['login_time'] = datetime.now(timezone.utc).timestamp()

    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    err = ""
    full_name = request.form.get("full_name", "")
    full_name, err = validation.validate_name_on_card(full_name)
    if err:
        return render_template(
            "register.html",
            error = "error in name: {0}".format(err)
        )
    email = request.form.get("email", "")
    email, err = validation.validate_billing_email(email)
    if err: 
        return render_template(
            "register.html",
            error = "error in email: {0}".format(err)
        )
    phone = request.form.get("phone", "")
    phone, err = validation.validate_phone_number(phone)
    if err: 
        return render_template(
            "register.html",
            error = "error in phone number: {0}".format(err)
        )
    password = request.form.get("password", "")
    password, err = validation.validate_password(password, "")
    if err:
        return render_template(
            "register.html",
            error = "error in password: {0}".format(err)
        )
    confirm_password = request.form.get("confirm_password", "")
    if confirm_password != password:
        return render_template(
            "register.html",
            error = "Password dosen't coincide"
        )

    if user_exists(email):
        return render_template(
            "register.html",
            error="This email is already registered. Try signing in."
        ), 400

    users = load_users()
    next_id = (max([u.get("id", 0) for u in users], default=0) + 1)
    password = encryption.hash_password(password)
    users.append({
        "id": next_id,
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "password": password,
        "role": "user",          
        "status": "active",
    })

    save_users(users)

    return redirect(url_for("login", registered="1"))

@app.route("/logout")
def logout():
    login_check = require_login()
    if login_check:
        return login_check
    session.clear()
    
    return render_template("login.html", info_message="Log out")


@app.get("/dashboard")
def dashboard():
    login_check = require_login()
    if login_check:  
        return login_check
    paid = request.args.get("paid") == "1"
    user = get_current_user()
    return render_template("dashboard.html", user_name=(user.get("full_name") if user else "User"), paid=paid)

@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_check = require_login()
    if login_check:  
        return login_check
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    form = {
        "full_name": user.get("full_name", ""),
        "email": user.get("email", ""),
        "phone": user.get("phone", ""),
    }

    field_errors = {}  
    success_msg = None

    if request.method == "POST":
        full_name = request.form.get("full_name", "")
        phone = request.form.get("phone", "")
        old_password = user.get("password")
        current_password = request.form.get("current_password", "")
        if not encryption.verify_password(current_password, old_password):
            return render_template(
                "profile.html",
                error = "Incorrect password"
        )
        new_password = request.form.get("new_password", "")
        new_password, err = validation.validate_password(new_password, "")
        if err:
            return render_template(
                "profile.html",
                error = "error in password: {0}".format(err)
        )
        confirm_new_password = request.form.get("confirm_new_password", "")
        if new_password != confirm_new_password:
            return render_template(
                "profile.html",
                error = "Password confirmation dosen't coincide"
        )   

        users = load_users()
        email_norm = (user.get("email") or "").strip().lower()
        new_password= encryption.hash_password(new_password)
        for u in users:
            if (u.get("email") or "").strip().lower() == email_norm:
                u["full_name"] = full_name
                u["phone"] = phone

                if new_password:
                    u["password"] = new_password
                break

        save_users(users)

        form["full_name"] = full_name
        form["phone"] = phone
        success_msg = "Profile updated successfully."

    return render_template(
        "profile.html",
        form=form,
        field_errors=field_errors,
        success_message=success_msg,
    )

@app.route("/error", methods=["GET", "POST"])
def error_page():
    cod_error = 0
    mesage = "error"
    return render_template("error.html", error = cod_error, mesage = mesage)


@app.get("/admin/users")
def admin_users():
    admin_check = require_admin()
    if admin_check:  
        return admin_check
    q = (request.args.get("q") or "").strip().lower()
    role = (request.args.get("role") or "all").strip().lower()
    status = (request.args.get("status") or "all").strip().lower()
    lockout = (request.args.get("lockout") or "all").strip().lower()

    users = [_user_with_defaults(u) for u in load_users()]

    # filtros
    if q:
        users = [
            u for u in users
            if q in (u.get("full_name","").lower()) or q in (u.get("email","").lower())
        ]

    if role != "all":
        users = [u for u in users if (u.get("role","user").lower() == role)]

    if status != "all":
        users = [u for u in users if (u.get("status","active").lower() == status)]

    if lockout != "all":
        if lockout == "locked":
            users = [u for u in users if (u.get("locked_until") or "").strip()]
        elif lockout == "not_locked":
            users = [u for u in users if not (u.get("locked_until") or "").strip()]

    users.sort(key=lambda u: (u.get("full_name","").lower(), u.get("id", 0)))

    return render_template(
        "admin_users.html",
        users=users,
        filters={"q": q, "role": role, "status": status, "lockout": lockout},
        total=len(users),
    )

@app.post("/admin/users/<int:user_id>/toggle")
def admin_toggle_user(user_id: int):
    users = load_users()
    for u in users:
        if int(u.get("id", 0)) == user_id:
            u.setdefault("status", "active")
            u["status"] = "disabled" if u["status"] == "active" else "active"
            break
    save_users(users)
    return redirect(url_for("admin_users"))

@app.post("/admin/users/<int:user_id>/role")
def admin_change_role(user_id: int):
    new_role = request.form.get("role", "user")

    users = load_users()
    for u in users:
        if int(u.get("id", 0)) == user_id:
            u["role"] = new_role
            break
    save_users(users)
    return redirect(url_for("admin_users"))

if __name__ == "__main__":
    app.run(debug=True)