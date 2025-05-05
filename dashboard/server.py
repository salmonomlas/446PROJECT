import os, json, qrcode, io, pyotp
from flask_wtf import CSRFProtect
from flask_cors import CORS
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file,
    abort,
    make_response
)
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

mongoUri = os.getenv("MONGO_URI", "mongodb://mongo:27017/")
mongoClient = MongoClient(mongoUri)
db          = mongoClient["dashboardDb"]
usersColl   = db["users"]

adminUser    = os.getenv("ADMIN_USER", "admin")
adminPwHash  = os.getenv("ADMIN_PW_HASH")
secretKey    = os.getenv("SECRET_KEY",   "changeme")
sessionTimeout = int(os.getenv("SESSION_TIMEOUT", "30"))

app = Flask(__name__, static_folder="static")
csrf = CSRFProtect(app)
CORS(app, origins=["https://localhost"], supports_credentials=True)
app.secret_key = secretKey
app.permanent_session_lifetime = timedelta(minutes=sessionTimeout)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True
)

USERS_FILE = "users.json"

def loadUsers():
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def saveUsers(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def loginRequired(f):
    from functools import wraps
    @wraps(f)
    def decoratedFunction(*args, **kwargs):
        if not session.get("loggedIn"):
            return redirect(url_for("showLoginPage"))
        return f(*args, **kwargs)
    return decoratedFunction

@app.route("/login", methods=["GET", "POST"])
def showLoginPage():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        userRec = usersColl.find_one({"_id": username})

        if userRec and check_password_hash(userRec["passwordHash"], password):
            session.clear()
            session["role"] = userRec.get("role", "user")

            if not userRec.get("mfaEnabled", False):
                session["loggedIn"] = True
                session["username"] = username
                return redirect(url_for("mfaSetup"))

            session["preMfaUser"] = username
            return redirect(url_for("mfaChallenge"))

        flash("Invalid username or password", "error")

    return render_template("login.html")

@app.route("/", methods=["GET"])
@loginRequired
def showhomePage():
    return render_template("home.html")

# ——— DUMMY ACTIONS - ROUTE TO SENSORS LATER ———
@app.route("/action1", methods=["POST"])
@loginRequired
def handleAction1():
    flash("Action 1 executed!", "info")
    return redirect(url_for("showhomePage"))

@app.route("/action2", methods=["POST"])
@loginRequired
def handleAction2():
    flash("Action 2 executed!", "info")
    return redirect(url_for("showhomePage"))

@app.route("/action3", methods=["POST"])
@loginRequired
def handleAction3():
    flash("Action 3 executed!", "info")
    return redirect(url_for("showhomePage"))

@app.route("/register", methods=["GET", "POST"])
def showRegisterPage():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or usersColl.find_one({"_id": username}):
            flash("Username already taken", "error")
            return redirect(url_for("showRegisterPage"))

        usersColl.insert_one({
            "_id": username,
            "passwordHash": generate_password_hash(password),
            "mfaEnabled": False, 
            "mfaSecret": None,
            "role": "user"
        }) 
        flash("Account created successfully", "info")
        return redirect(url_for("showLoginPage"))

    return render_template("register.html")

@app.route("/mfa-setup", methods=["GET", "POST"])
@loginRequired
def mfaSetup():
    if request.method == "GET":
        secret = pyotp.random_base32()
        session["mfaTempSecret"] = secret
        return render_template("mfa_setup.html")

    token  = request.form.get("token", "").strip()
    secret = session.get("mfaTempSecret")
    if not secret or not pyotp.TOTP(secret).verify(token, valid_window=1):
        return render_template("mfa_setup.html",
                               error="Invalid code, please try again.")

    username = session.get("username")
    usersColl.update_one(
        {"_id": username},
        {"$set": {"mfaEnabled": True, "mfaSecret": secret}}
    )
    session.pop("mfaTempSecret", None)
    if session.get("role") == "admin":
        return redirect(url_for("showSecurityPage"))
    else:
        return redirect(url_for("showhomePage"))

@app.route("/mfa-setup/qrcode", methods=["GET"])
@loginRequired
def mfaSetupQrCode():
    secret = session.get("mfaTempSecret")
    if not secret:
        abort(404)

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=session.get("username", "user"),
        issuer_name="Dashboard"
    )

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return send_file(buf, mimetype="image/png")

@app.route("/mfa-challenge", methods=["GET", "POST"])
def mfaChallenge():
    if "preMfaUser" not in session:
        return redirect(url_for("showLoginPage"))

    if request.method == "POST":
        username = session["preMfaUser"]
        token    = request.form.get("token", "").strip()
        userRec  = usersColl.find_one({"_id": username})

        if userRec and pyotp.TOTP(userRec["mfaSecret"]).verify(token, valid_window=1):
            session.clear()
            session["loggedIn"] = True
            session["username"] = username
            session["role"]     = userRec.get("role", "user")

            if session["role"] == "admin":
                return redirect(url_for("showSecurityPage"))
            return redirect(url_for("showhomePage"))

        flash("Invalid code, please try again.", "error")

    return render_template("mfa_challenge.html")

@app.route("/security", methods=["GET"])
@loginRequired
def showSecurityPage():
    if session.get("role") != "admin":
        abort(403)
    users = list(usersColl.find({}, {"_id": 1, "role": 1}))
    usersList = [{"username": u["_id"], "role": u.get("role", "user")} for u in users]
    return render_template("security.html", users=usersList)

@app.route("/security/update-role", methods=["POST"])
@loginRequired
def updateUserRole():
    # Only admins may perform updates
    if session.get("role") != "admin":
        abort(403)

    username = request.form.get("username")
    newRole  = request.form.get("role")
    if username and newRole in ("user", "admin"):
        usersColl.update_one(
            {"_id": username},
            {"$set": {"role": newRole}}
        )
        flash(f"Role of {username} changed to {newRole}", "info")
    else:
        flash("Invalid user or role", "error")

    return redirect(url_for("showSecurityPage"))

@app.route("/logout", methods=["POST"])
def handleLogout():
    session.clear()
    return render_template("post_logout.html")

@app.after_request
def addSecurityHeaders(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"]        = "no-cache"
    response.headers["Expires"]       = "0"
    response.headers["X-Frame-Optinos"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "base-uri 'self'; "
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
        "manifest-src 'self'; "
        "upgrade-insecure-requests; "
    )
                                                    
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)