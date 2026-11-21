import os
import re
import tempfile
import time
import threading
import uuid
from collections import Counter
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, abort, send_from_directory)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from bson import ObjectId
from bson.errors import InvalidId
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError, PyMongoError
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)
try:
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
except OSError:
    # Serverless hosts may have a read-only filesystem; fall back to temp storage.
    app.config["UPLOAD_FOLDER"] = os.path.join(tempfile.gettempdir(), "campus_connect_uploads")
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

CATEGORIES = ["Classroom Issues", "Electricity Problems", "Water Problems", "Internet/WiFi",
              "Library Issues", "Hostel Issues", "Cleanliness", "Other"]
STATUSES = ["Pending", "Under Review", "In Progress", "Resolved", "Rejected"]

# Minimal in-process login throttle (single-worker deployments).
_login_attempts = {}
_login_lock = threading.Lock()
LOGIN_WINDOW_SECONDS = 10 * 60
LOGIN_MAX_ATTEMPTS = 5

_mongo_client = None
_indexes_ready = False
# Keep timeouts short so serverless cold starts stay under function limits.
DB_TIMEOUT_MS = 4000


# ---------------------------------------------------------------- database

def db():
    """Return the MongoDB database, creating the client lazily."""
    global _mongo_client
    uri = app.config["MONGODB_URI"]
    if not uri:
        raise RuntimeError("MONGODB_URI is not configured")
    if _mongo_client is None:
        _mongo_client = MongoClient(
            uri,
            serverSelectionTimeoutMS=DB_TIMEOUT_MS,
            connectTimeoutMS=DB_TIMEOUT_MS,
            tz_aware=False,
        )
    return _mongo_client[app.config["MONGODB_DB"]]


def col(name):
    return db()[name]


def oid(value):
    try:
        return ObjectId(str(value))
    except (InvalidId, TypeError):
        return None


def doc_or_404(collection, value):
    _id = oid(value)
    found = col(collection).find_one({"_id": _id}) if _id else None
    if not found:
        abort(404)
    return found


def student_by_id(student_id):
    _id = oid(student_id)
    return col("students").find_one({"_id": _id}) if _id else None


def students_map(student_ids):
    ids = [oid(s) for s in set(student_ids) if oid(s)]
    if not ids:
        return {}
    return {str(s["_id"]): s for s in col("students").find({"_id": {"$in": ids}})}


def ensure_indexes():
    """Create collections and indexes once per process (idempotent)."""
    global _indexes_ready
    if _indexes_ready:
        return
    col("students").create_index([("username", ASCENDING)], unique=True)
    col("students").create_index([("email", ASCENDING)], unique=True)
    col("students").create_index(
        [("student_id", ASCENDING)], unique=True,
        partialFilterExpression={"student_id": {"$type": "string"}})
    col("students").create_index([("full_name", ASCENDING)])
    col("students").create_index([("department", ASCENDING)])
    col("admins").create_index([("username", ASCENDING)], unique=True)
    col("admins").create_index([("email", ASCENDING)], unique=True)
    col("complaints").create_index([("student_id", ASCENDING)])
    col("complaints").create_index([("status", ASCENDING)])
    col("complaints").create_index([("category", ASCENDING)])
    col("complaints").create_index([("created_at", ASCENDING)])
    col("complaint_updates").create_index([("complaint_id", ASCENDING)])
    col("events").create_index([("event_date", ASCENDING)])
    col("event_registrations").create_index(
        [("event_id", ASCENDING), ("student_id", ASCENDING)], unique=True)
    col("lost_found").create_index([("student_id", ASCENDING)])
    col("lost_found").create_index([("item_name", ASCENDING)])
    col("posts").create_index([("status", ASCENDING)])
    col("posts").create_index([("created_at", ASCENDING)])
    col("comments").create_index([("post_id", ASCENDING)])
    col("post_votes").create_index(
        [("post_id", ASCENDING), ("student_id", ASCENDING), ("vote_type", ASCENDING)],
        unique=True)
    col("post_reports").create_index(
        [("post_id", ASCENDING), ("student_id", ASCENDING)], unique=True)
    col("notifications").create_index([("student_id", ASCENDING), ("is_read", ASCENDING)])
    _indexes_ready = True


# ---------------------------------------------------------------- helpers

def current_user():
    return session.get("user")


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            user_role = user.get("role")
            if user_role not in ("admin", "student"):
                session.clear()
                return redirect(url_for("login"))
            collection = "admins" if user_role == "admin" else "students"
            _id = oid(user.get("id"))
            try:
                account = col(collection).find_one({"_id": _id}, {"is_active": 1}) if _id else None
            except Exception:
                # Database unreachable: refuse access rather than trust an unverified session.
                abort(503)
            if not account or (user_role == "student" and not account.get("is_active", 1)):
                session.clear()
                flash("Your account is no longer active. Please contact the administrator.", "danger")
                return redirect(url_for("login"))
            if role and user_role != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def login_key():
    return (request.remote_addr or "unknown", request.form.get("identity", "").strip().lower())


def login_is_throttled(key):
    now = time.monotonic()
    with _login_lock:
        attempts = [t for t in _login_attempts.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
        _login_attempts[key] = attempts
        return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_login_failure(key):
    with _login_lock:
        _login_attempts.setdefault(key, []).append(time.monotonic())


def clear_login_failures(key):
    with _login_lock:
        _login_attempts.pop(key, None)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]


def is_image_file(path, ext):
    with open(path, "rb") as handle:
        head = handle.read(16)
    if ext == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "gif":
        return head.startswith((b"GIF87a", b"GIF89a"))
    if ext == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    return False


def save_upload(field):
    upload = request.files.get(field)
    if not upload or not upload.filename:
        return None
    if not allowed_file(upload.filename):
        raise ValueError("Only PNG, JPG, JPEG, GIF and WEBP images are allowed.")
    ext = upload.filename.rsplit(".", 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    upload.save(path)
    if not is_image_file(path, ext):
        os.remove(path)
        raise ValueError("The uploaded file is not a valid image.")
    return filename


def delete_upload(filename):
    if not filename:
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], os.path.basename(filename))
    try:
        os.remove(path)
    except OSError:
        pass


def can_access_upload(filename):
    user = current_user()
    if not user:
        return False
    if user.get("role") == "admin":
        return True
    if user.get("role") != "student":
        return False
    for table in ("complaints", "lost_found", "posts"):
        if col(table).find_one({"image": filename, "student_id": user["id"]}, {"_id": 1}):
            return True
    return False


def rx(value):
    """Case-insensitive, literal search term for $regex."""
    return {"$regex": re.escape(value), "$options": "i"}


def like_search(collection, fields, term, extra=None, sort=("created_at", -1), limit=None):
    flt = {}
    if extra:
        flt.update(extra)
    if term:
        flt["$or"] = [{f: rx(term)} for f in fields]
    cursor = col(collection).find(flt).sort(*sort)
    if limit:
        cursor = cursor.limit(limit)
    return list(cursor)


def monthly_counts(docs):
    counter = Counter()
    for doc in docs:
        stamp = doc.get("created_at")
        if isinstance(stamp, datetime):
            counter[(stamp.year, stamp.month)] += 1
    return [{"label": datetime(year, month, 1).strftime("%b %Y"), "total": total}
            for (year, month), total in sorted(counter.items())]


def department_counts():
    students = {str(s["_id"]): (s.get("department") or "Unspecified")
                for s in col("students").find({}, {"department": 1})}
    ids = [c.get("student_id") for c in col("complaints").find({}, {"student_id": 1})]
    return [{"label": label, "total": total}
            for label, total in Counter(students.get(i, "Unspecified") for i in ids).most_common()]


def registration_counts(events=None):
    counts = Counter(str(r["event_id"]) for r in col("event_registrations").find({}, {"event_id": 1}))
    events = events if events is not None else list(col("events").find())
    return [{"label": e["title"], "total": counts[str(e["_id"])]} for e in events]


def notify(student_id, title, message, link=None):
    col("notifications").insert_one({
        "student_id": student_id, "title": title, "message": message,
        "link": link, "is_read": 0, "created_at": datetime.utcnow(),
    })


def ensure_admin():
    username = app.config["ADMIN_USERNAME"]
    email = app.config["ADMIN_EMAIL"]
    password = app.config["ADMIN_PASSWORD"]
    if any(v == "CHANGE_ME" or not v for v in (username, email, password)):
        print("Admin setup skipped: set ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD in .env")
        return
    existing = col("admins").find_one({"$or": [{"username": username}, {"email": email}]})
    if not existing:
        col("admins").insert_one({
            "username": username, "email": email,
            "password_hash": generate_password_hash(password),
            "created_at": datetime.utcnow(),
        })
        print(f"Initial admin created for {username}")


@app.context_processor
def inject_globals():
    unread = 0
    user = current_user()
    if user and user.get("role") == "student":
        try:
            unread = col("notifications").count_documents(
                {"student_id": user["id"], "is_read": 0})
        except Exception:
            pass
    return {"current_user": user, "unread_notifications": unread, "categories": CATEGORIES}


# ---------------------------------------------------------------- public

@app.route("/")
def index():
    try:
        events = list(col("events").find({"event_date": {"$gte": datetime.utcnow()}})
                      .sort("event_date", ASCENDING).limit(3))
    except Exception:  # Database unreachable or URI not configured yet.
        events = []
    return render_template("index.html", events=events)


@app.route("/health")
def health():
    if not app.config["MONGODB_URI"]:
        return {"status": "error", "database": "MONGODB_URI is not configured"}, 503
    try:
        db().command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception as exc:
        return {"status": "error", "database": str(exc)}, 503


@app.route("/media/events/<path:filename>")
def event_media(filename):
    if os.path.basename(filename) != filename:
        abort(404)
    try:
        known = col("events").find_one({"banner": filename}, {"_id": 1})
    except Exception:
        abort(503)
    if not known:
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/media/<path:filename>")
@login_required()
def media(filename):
    if os.path.basename(filename) != filename or not can_access_upload(filename):
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ---------------------------------------------------------------- auth

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        department = request.form.get("department", "").strip()
        student_id = request.form.get("student_id", "").strip() or None
        password = request.form.get("password", "")

        if not all([name, username, email, password]) or len(password) < 8:
            flash("Complete all required fields. Password must be at least 8 characters.", "danger")
        elif not re.match(r"^[A-Za-z0-9_.-]{3,60}$", username):
            flash("Username must be 3–60 characters and use letters, numbers, dot, dash or underscore.", "danger")
        elif len(name) > 120 or len(email) > 160 or len(department) > 100 or (student_id and len(student_id) > 50):
            flash("One or more fields are too long.", "danger")
        else:
            try:
                email = validate_email(email, check_deliverability=False).normalized
            except EmailNotValidError:
                flash("Enter a valid email address.", "danger")
            else:
                try:
                    col("students").insert_one({
                        "full_name": name, "username": username, "email": email,
                        "department": department, "student_id": student_id,
                        "password_hash": generate_password_hash(password),
                        "is_active": 1, "created_at": datetime.utcnow(),
                    })
                    flash("Registration successful. You can now log in.", "success")
                    return redirect(url_for("login"))
                except DuplicateKeyError:
                    flash("That username, email or student ID is already registered.", "danger")
                except PyMongoError:
                    flash("Could not create your account. Please try again.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "student")
        if role not in ("admin", "student"):
            role = "student"
        key = login_key()

        if login_is_throttled(key):
            flash("Too many failed attempts. Please try again in 10 minutes.", "danger")
        elif not identity or not password:
            flash("Enter your username and password.", "danger")
        else:
            collection = "admins" if role == "admin" else "students"
            try:
                user = col(collection).find_one(
                    {"$or": [{"username": identity}, {"email": identity}]})
            except Exception:
                flash("Database is not available yet. Please try again later.", "danger")
                user = None
            if user and check_password_hash(user["password_hash"], password):
                if role == "student" and not user.get("is_active", 1):
                    flash("Your student account is inactive. Contact the campus administrator.", "danger")
                else:
                    clear_login_failures(key)
                    session.clear()
                    session.permanent = True
                    session["user"] = {"id": str(user["_id"]),
                                       "name": user.get("full_name", user.get("username")),
                                       "username": user["username"], "role": role}
                    flash("Welcome back!", "success")
                    return redirect(url_for("admin_dashboard" if role == "admin" else "student_dashboard"))
            else:
                record_login_failure(key)
                flash("Invalid login details.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required()
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------- student

@app.route("/student")
@login_required("student")
def student_dashboard():
    sid = current_user()["id"]
    own = list(col("complaints").find({"student_id": sid}, {"status": 1}))
    statuses = Counter(c["status"] for c in own)
    stats = {"total": len(own), "pending": statuses.get("Pending", 0),
             "progress": statuses.get("In Progress", 0), "resolved": statuses.get("Resolved", 0)}
    joined = col("event_registrations").count_documents({"student_id": sid})
    votes = col("post_votes").count_documents({"student_id": sid})
    recent = list(col("complaints").find({"student_id": sid})
                  .sort("created_at", -1).limit(5))
    students = students_map([r["student_id"] for r in recent])
    for row in recent:
        row["full_name"] = students.get(row["student_id"], {}).get("full_name", "")
    return render_template("student_dashboard.html", stats=stats, joined=joined,
                           votes=votes, recent=recent)


@app.route("/complaints", methods=["GET", "POST"])
@login_required("student")
def complaints():
    sid = current_user()["id"]
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category")
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        if not title or category not in CATEGORIES or not description or not location:
            flash("Complete all complaint fields.", "danger")
        else:
            try:
                image = save_upload("image")
                col("complaints").insert_one({
                    "student_id": sid, "title": title, "category": category,
                    "description": description, "location": location, "image": image,
                    "status": "Pending", "admin_response": None,
                    "created_at": datetime.utcnow(), "updated_at": datetime.utcnow(),
                })
                flash("Your complaint has been submitted.", "success")
                return redirect(url_for("complaints"))
            except (ValueError, PyMongoError) as exc:
                flash(str(exc) if isinstance(exc, ValueError)
                      else "Could not save complaint. Check database setup.", "danger")
    search = request.args.get("q", "").strip()
    rows = like_search("complaints", ["title", "category", "status"], search,
                       extra={"student_id": sid})
    return render_template("complaints.html", rows=rows, search=search)


@app.route("/complaints/<string:cid>")
@login_required()
def complaint_details(cid):
    row = doc_or_404("complaints", cid)
    student = student_by_id(row.get("student_id"))
    row["full_name"] = student.get("full_name", "") if student else ""
    if current_user()["role"] == "student" and row["student_id"] != current_user()["id"]:
        abort(403)
    updates = list(col("complaint_updates").find({"complaint_id": str(row["_id"])})
                   .sort("created_at", -1))
    admins = {str(a["_id"]): a for a in col("admins").find()}
    for update in updates:
        admin = admins.get(str(update.get("admin_id")))
        update["admin_name"] = admin["username"] if admin else None
    return render_template("complaint_details.html", row=row, updates=updates)


@app.route("/admin/complaints/<string:cid>/update", methods=["POST"])
@login_required("admin")
def update_complaint(cid):
    row = doc_or_404("complaints", cid)
    status = request.form.get("status")
    if status not in STATUSES:
        abort(400)
    response = request.form.get("response", "").strip()
    col("complaints").update_one({"_id": row["_id"]},
                                 {"$set": {"status": status, "admin_response": response,
                                           "updated_at": datetime.utcnow()}})
    col("complaint_updates").insert_one({
        "complaint_id": str(row["_id"]), "admin_id": current_user()["id"],
        "status": status, "response": response, "created_at": datetime.utcnow(),
    })
    notify(row["student_id"], "Complaint updated",
           f"Complaint #{str(row['_id'])[:8]} status: {status}. {response}",
           url_for("complaint_details", cid=str(row["_id"])))
    flash("Complaint updated and student notified.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/lost-found", methods=["GET", "POST"])
@login_required("student")
def lost_found():
    if request.method == "POST":
        report_type = request.form.get("report_type")
        item_name = request.form.get("item_name", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        item_date = request.form.get("item_date")
        if report_type not in ("Lost", "Found") or not all([item_name, description, location, item_date]):
            flash("Complete all item report fields.", "danger")
        else:
            try:
                image = save_upload("image")
                col("lost_found").insert_one({
                    "student_id": current_user()["id"], "report_type": report_type,
                    "item_name": item_name, "description": description,
                    "location": location, "item_date": item_date, "image": image,
                    "status": "Open", "created_at": datetime.utcnow(),
                })
                flash("Your item report has been posted.", "success")
                return redirect(url_for("lost_found"))
            except (ValueError, PyMongoError) as exc:
                flash(str(exc) if isinstance(exc, ValueError) else "Could not save report.", "danger")
    q = request.args.get("q", "").strip()
    rows = like_search("lost_found", ["item_name", "description", "location"], q)
    students = students_map([r["student_id"] for r in rows])
    for row in rows:
        row["full_name"] = students.get(row["student_id"], {}).get("full_name", "")
    return render_template("lost_found.html", rows=rows, search=q)


@app.route("/lost-found/<string:item_id>/status", methods=["POST"])
@login_required("student")
def item_status(item_id):
    row = doc_or_404("lost_found", item_id)
    if row["student_id"] != current_user()["id"]:
        abort(403)
    status = request.form.get("status")
    if status not in ["Open", "Claimed", "Closed"]:
        abort(400)
    col("lost_found").update_one({"_id": row["_id"]}, {"$set": {"status": status}})
    return redirect(url_for("lost_found"))


@app.route("/lost-found/<string:item_id>/contact", methods=["POST"])
@login_required("student")
def item_contact(item_id):
    row = doc_or_404("lost_found", item_id)
    student = student_by_id(row.get("student_id"))
    if not student:
        abort(404)
    if row["student_id"] == current_user()["id"]:
        flash("This is your own report.", "info")
    else:
        flash(f"Contact {student.get('full_name', 'the owner')}: {student.get('email', '')}", "info")
    return redirect(url_for("lost_found"))


@app.route("/events")
@login_required("student")
def events():
    sid = current_user()["id"]
    all_events = list(col("events").find().sort("event_date", ASCENDING))
    joined = {str(r["event_id"]) for r in
              col("event_registrations").find({"student_id": sid}, {"event_id": 1})}
    counts = Counter(str(r["event_id"]) for r in
                     col("event_registrations").find({}, {"event_id": 1}))
    rows = []
    for event in all_events:
        key = str(event["_id"])
        event["attendees"] = counts.get(key, 0)
        event["joined"] = key in joined
        rows.append(event)
    return render_template("events.html", rows=rows)


@app.route("/events/<string:eid>/join", methods=["POST"])
@login_required("student")
def join_event(eid):
    event = doc_or_404("events", eid)
    when = event.get("event_date")
    if not isinstance(when, datetime) or when < datetime.utcnow():
        abort(400)
    try:
        col("event_registrations").insert_one({
            "event_id": str(event["_id"]), "student_id": current_user()["id"],
            "registered_at": datetime.utcnow(),
        })
        flash("You joined the event.", "success")
    except DuplicateKeyError:
        flash("You may already be registered for this event.", "warning")
    return redirect(url_for("events"))


@app.route("/events/<string:eid>/cancel", methods=["POST"])
@login_required("student")
def cancel_event(eid):
    event = doc_or_404("events", eid)
    col("event_registrations").delete_one({"event_id": str(event["_id"]),
                                           "student_id": current_user()["id"]})
    flash("Registration cancelled.", "info")
    return redirect(url_for("events"))


@app.route("/discussions", methods=["GET", "POST"])
@login_required("student")
def discussions():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title or not body:
            flash("A title and description are required.", "danger")
        else:
            try:
                image = save_upload("image")
                col("posts").insert_one({
                    "student_id": current_user()["id"], "title": title, "body": body,
                    "image": image, "status": "Pending", "created_at": datetime.utcnow(),
                })
                flash("Post submitted for admin approval.", "success")
                return redirect(url_for("discussions"))
            except (ValueError, PyMongoError) as exc:
                flash(str(exc) if isinstance(exc, ValueError) else "Could not create post.", "danger")
    q = request.args.get("q", "").strip()
    rows = like_search("posts", ["title", "body"], q, extra={"status": "Approved"})
    students = students_map([p["student_id"] for p in rows])
    post_ids = [str(p["_id"]) for p in rows]
    likes = Counter(str(v["post_id"]) for v in
                    col("post_votes").find({"post_id": {"$in": post_ids}, "vote_type": "Like"},
                                           {"post_id": 1}))
    upvotes = Counter(str(v["post_id"]) for v in
                      col("post_votes").find({"post_id": {"$in": post_ids}, "vote_type": "Upvote"},
                                             {"post_id": 1}))
    comments = Counter(str(c["post_id"]) for c in
                       col("comments").find({"post_id": {"$in": post_ids}}, {"post_id": 1}))
    for post in rows:
        key = str(post["_id"])
        post["full_name"] = students.get(post["student_id"], {}).get("full_name", "")
        post["likes"] = likes.get(key, 0)
        post["upvotes"] = upvotes.get(key, 0)
        post["comment_count"] = comments.get(key, 0)
    return render_template("discussions.html", rows=rows, search=q)


@app.route("/posts/<string:pid>/comment", methods=["POST"])
@login_required("student")
def comment(pid):
    post = doc_or_404("posts", pid)
    if post.get("status") != "Approved":
        abort(404)
    body = request.form.get("body", "").strip()
    if body:
        col("comments").insert_one({
            "post_id": str(post["_id"]), "student_id": current_user()["id"],
            "body": body, "created_at": datetime.utcnow(),
        })
    return redirect(url_for("discussions"))


@app.route("/posts/<string:pid>/vote/<vote_type>", methods=["POST"])
@login_required("student")
def vote(pid, vote_type):
    if vote_type not in ["Like", "Upvote"]:
        abort(400)
    post = doc_or_404("posts", pid)
    if post.get("status") != "Approved":
        abort(404)
    try:
        col("post_votes").insert_one({
            "post_id": str(post["_id"]), "student_id": current_user()["id"],
            "vote_type": vote_type, "created_at": datetime.utcnow(),
        })
        flash(f"{vote_type} recorded.", "success")
    except DuplicateKeyError:
        flash(f"You already gave this {vote_type.lower()}.", "info")
    return redirect(url_for("discussions"))


@app.route("/posts/<string:pid>/report", methods=["POST"])
@login_required("student")
def report_post(pid):
    post = doc_or_404("posts", pid)
    if post.get("status") != "Approved":
        abort(404)
    reason = request.form.get("reason", "").strip()[:255]
    try:
        col("post_reports").insert_one({
            "post_id": str(post["_id"]), "student_id": current_user()["id"],
            "reason": reason, "created_at": datetime.utcnow(),
        })
        flash("Report submitted for admin review.", "info")
    except DuplicateKeyError:
        flash("You have already reported this post.", "info")
    return redirect(url_for("discussions"))


@app.route("/profile", methods=["GET", "POST"])
@login_required("student")
def profile():
    sid = current_user()["id"]
    if request.method == "POST":
        action = request.form.get("action")
        if action == "profile":
            name = request.form.get("full_name", "").strip()
            department = request.form.get("department", "").strip()
            student_id = request.form.get("student_id", "").strip() or None
            if not name or len(name) > 120 or len(department) > 100 or (student_id and len(student_id) > 50):
                flash("Check the length of your profile details.", "danger")
            else:
                try:
                    col("students").update_one(
                        {"_id": oid(sid)},
                        {"$set": {"full_name": name, "department": department,
                                  "student_id": student_id}})
                    session["user"]["name"] = name
                    flash("Profile updated.", "success")
                except DuplicateKeyError:
                    flash("That student ID is already in use.", "danger")
        elif action == "password":
            row = col("students").find_one({"_id": oid(sid)}, {"password_hash": 1})
            if not check_password_hash(row["password_hash"], request.form.get("current_password", "")):
                flash("Current password is incorrect.", "danger")
            elif len(request.form.get("new_password", "")) < 8:
                flash("New password must be at least 8 characters.", "danger")
            else:
                col("students").update_one({"_id": oid(sid)},
                                           {"$set": {"password_hash":
                                                     generate_password_hash(request.form["new_password"])}})
                flash("Password changed.", "success")
        return redirect(url_for("profile"))
    row = doc_or_404("students", sid)
    return render_template("profile.html", row=row)


@app.route("/notifications")
@login_required("student")
def notifications():
    rows = list(col("notifications").find({"student_id": current_user()["id"]})
                .sort("created_at", -1))
    return render_template("notifications.html", rows=rows)


@app.route("/notifications/read", methods=["POST"])
@login_required("student")
def notifications_read():
    col("notifications").update_many({"student_id": current_user()["id"]},
                                     {"$set": {"is_read": 1}})
    flash("All notifications marked as read.", "info")
    return redirect(url_for("notifications"))


# ---------------------------------------------------------------- admin

@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    stats = {
        "students": col("students").count_documents({}),
        "complaints": col("complaints").count_documents({}),
        "pending": col("complaints").count_documents({"status": "Pending"}),
        "resolved": col("complaints").count_documents({"status": "Resolved"}),
        "posts": col("posts").count_documents({}),
        "events": col("events").count_documents({}),
    }
    complaints_rows = list(col("complaints").find().sort("created_at", -1).limit(10))
    students = students_map([c["student_id"] for c in complaints_rows])
    for row in complaints_rows:
        row["full_name"] = students.get(row["student_id"], {}).get("full_name", "")
    recent_students = list(col("students").find().sort("created_at", -1).limit(8))
    all_complaints = list(col("complaints").find({}, {"created_at": 1}))
    monthly = monthly_counts(all_complaints)[:12]
    dept = department_counts()[:8]
    return render_template("admin_dashboard.html", stats=stats, complaints=complaints_rows,
                           students=recent_students, monthly=monthly, dept=dept)


@app.route("/admin/students")
@login_required("admin")
def manage_students():
    q = request.args.get("q", "").strip()
    rows = like_search("students", ["full_name", "username", "email"], q,
                       sort=("created_at", -1))
    return render_template("admin_students.html", rows=rows, search=q)


@app.route("/admin/students/<string:sid>/toggle", methods=["POST"])
@login_required("admin")
def toggle_student(sid):
    _id = oid(sid)
    if not _id:
        abort(404)
    row = col("students").find_one({"_id": _id}, {"is_active": 1})
    if not row:
        abort(404)
    col("students").update_one({"_id": _id},
                               {"$set": {"is_active": 0 if row.get("is_active", 1) else 1}})
    flash("Student status updated.", "success")
    return redirect(url_for("manage_students"))


@app.route("/admin/posts")
@login_required("admin")
def manage_posts():
    rows = list(col("posts").find().sort("created_at", -1))
    students = students_map([p["student_id"] for p in rows])
    for post in rows:
        post["full_name"] = students.get(post["student_id"], {}).get("full_name", "")
    return render_template("admin_posts.html", rows=rows)


@app.route("/admin/posts/<string:pid>/<action>", methods=["POST"])
@login_required("admin")
def moderate_post(pid, action):
    post = doc_or_404("posts", pid)
    status = {"approve": "Approved", "reject": "Rejected"}.get(action)
    if status:
        col("posts").update_one({"_id": post["_id"]}, {"$set": {"status": status}})
    elif action == "delete":
        key = str(post["_id"])
        col("comments").delete_many({"post_id": key})
        col("post_votes").delete_many({"post_id": key})
        col("post_reports").delete_many({"post_id": key})
        col("posts").delete_one({"_id": post["_id"]})
        delete_upload(post.get("image"))
    else:
        abort(400)
    return redirect(url_for("manage_posts"))


@app.route("/admin/reports")
@login_required("admin")
def admin_reports():
    rows = list(col("post_reports").find().sort("created_at", -1))
    posts = {str(p["_id"]): p for p in col("posts").find()}
    students = students_map([r["student_id"] for r in rows])
    reports = []
    for row in rows:
        post = posts.get(row["post_id"])
        if not post:
            col("post_reports").delete_one({"_id": row["_id"]})
            continue
        row["post_title"] = post["title"]
        row["reporter"] = students.get(row["student_id"], {}).get("full_name", "")
        reports.append(row)
    return render_template("admin_reports.html", rows=reports)


@app.route("/admin/reports/<string:rid>/dismiss", methods=["POST"])
@login_required("admin")
def dismiss_report(rid):
    _id = oid(rid)
    if not _id or not col("post_reports").find_one({"_id": _id}):
        abort(404)
    col("post_reports").delete_one({"_id": _id})
    flash("Report dismissed.", "info")
    return redirect(url_for("admin_reports"))


@app.route("/admin/reports/<string:rid>/takedown", methods=["POST"])
@login_required("admin")
def takedown_report(rid):
    _id = oid(rid)
    report = col("post_reports").find_one({"_id": _id}) if _id else None
    if not report:
        abort(404)
    col("posts").update_one({"_id": oid(report["post_id"])},
                            {"$set": {"status": "Pending"}})
    col("post_reports").delete_many({"post_id": report["post_id"]})
    flash("Post returned to the moderation queue.", "success")
    return redirect(url_for("admin_reports"))


@app.route("/admin/events", methods=["GET", "POST"])
@login_required("admin")
def manage_events():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        venue = request.form.get("venue", "").strip()
        event_date = request.form.get("event_date")
        if not all([title, description, venue, event_date]):
            flash("Complete all event fields.", "danger")
        else:
            try:
                when = datetime.strptime(event_date, "%Y-%m-%dT%H:%M")
            except ValueError:
                flash("Enter a valid date and time.", "danger")
            else:
                try:
                    banner = save_upload("banner")
                    col("events").insert_one({
                        "title": title, "description": description, "venue": venue,
                        "event_date": when, "banner": banner,
                        "created_by": current_user()["id"],
                        "created_at": datetime.utcnow(),
                    })
                    flash("Event created.", "success")
                    return redirect(url_for("manage_events"))
                except (ValueError, PyMongoError) as exc:
                    flash(str(exc) if isinstance(exc, ValueError) else "Could not create event.", "danger")
    rows = list(col("events").find().sort("event_date", -1))
    return render_template("admin_events.html", rows=rows)


@app.route("/admin/events/<string:eid>/delete", methods=["POST"])
@login_required("admin")
def delete_event(eid):
    event = doc_or_404("events", eid)
    col("event_registrations").delete_many({"event_id": str(event["_id"])})
    col("events").delete_one({"_id": event["_id"]})
    delete_upload(event.get("banner"))
    return redirect(url_for("manage_events"))


@app.route("/admin/events/<string:eid>/registrations")
@login_required("admin")
def event_registrations(eid):
    event = doc_or_404("events", eid)
    regs = list(col("event_registrations").find({"event_id": str(event["_id"])})
                .sort("registered_at", ASCENDING))
    students = students_map([r["student_id"] for r in regs])
    rows = []
    for reg in regs:
        student = students.get(reg["student_id"], {})
        rows.append({"full_name": student.get("full_name", ""),
                     "username": student.get("username", ""),
                     "email": student.get("email", ""),
                     "department": student.get("department", ""),
                     "registered_at": reg.get("registered_at")})
    return render_template("admin_registrations.html", event=event, rows=rows)


@app.route("/admin/lost-found")
@login_required("admin")
def admin_lost_found():
    rows = list(col("lost_found").find().sort("created_at", -1))
    students = students_map([r["student_id"] for r in rows])
    for row in rows:
        row["full_name"] = students.get(row["student_id"], {}).get("full_name", "")
    return render_template("admin_lost_found.html", rows=rows)


@app.route("/admin/lost-found/<string:item_id>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_item(item_id):
    item = doc_or_404("lost_found", item_id)
    col("lost_found").delete_one({"_id": item["_id"]})
    delete_upload(item.get("image"))
    return redirect(url_for("admin_lost_found"))


@app.route("/admin/analytics")
@login_required("admin")
def analytics():
    status = [{"label": s["_id"], "total": s["total"]} for s in
              col("complaints").aggregate([{"$group": {"_id": "$status", "total": {"$sum": 1}}}])]
    monthly = monthly_counts(list(col("complaints").find({}, {"created_at": 1})))
    dept = department_counts()
    participation = registration_counts()[:10]
    registrations = monthly_counts(list(col("students").find({}, {"created_at": 1})))
    return render_template("analytics.html", status=status, monthly=monthly, dept=dept,
                           participation=participation, registrations=registrations)


@app.route("/admin/settings")
@login_required("admin")
def settings():
    return render_template("admin_settings.html")


# ---------------------------------------------------------------- errors

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400,
                           message="Your form session has expired. Reload the page and try again."), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def missing(e):
    return render_template("error.html", code=404, message="The page you requested could not be found."), 404


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413, message="Upload is too large. Maximum size is 5 MB."), 413


@app.errorhandler(503)
def unavailable(e):
    return render_template("error.html", code=503,
                           message="The database is temporarily unavailable. Please try again shortly."), 503


def _bootstrap():
    try:
        ensure_indexes()
        ensure_admin()
    except Exception as exc:  # Database may be unreachable on serverless hosts.
        print("Database bootstrap unavailable:", exc)


if os.getenv("VERCEL"):
    # On serverless, don't block the import on a database connection.
    threading.Thread(target=_bootstrap, daemon=True).start()
else:
    _bootstrap()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
