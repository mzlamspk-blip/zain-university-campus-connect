import os
import re
import tempfile
import time
import threading
import uuid
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, abort, send_from_directory)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
import mysql.connector
from mysql.connector import Error
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


def db():
    return mysql.connector.connect(
        host=app.config["DB_HOST"], port=app.config["DB_PORT"],
        user=app.config["DB_USER"], password=app.config["DB_PASSWORD"],
        database=app.config["DB_NAME"], autocommit=False
    )


def query(sql, params=(), one=False, write=False):
    conn = db()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql, params)
        if write:
            conn.commit()
            return cur.lastrowid
        return cur.fetchone() if one else cur.fetchall()
    except Error:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


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
            table = "admins" if user_role == "admin" else "students"
            account = query(f"SELECT id{', is_active' if user_role == 'student' else ''} "
                            f"FROM {table} WHERE id=%s", (user.get("id"),), one=True)
            if not account or (user_role == "student" and not account["is_active"]):
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
        row = query(f"SELECT 1 AS ok FROM {table} WHERE image=%s AND student_id=%s",
                    (filename, user["id"]), one=True)
        if row:
            return True
    return False


def like_term(value):
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def notify(student_id, title, message, link=None):
    query("INSERT INTO notifications (student_id,title,message,link) VALUES (%s,%s,%s,%s)",
          (student_id, title, message, link), write=True)


def ensure_admin():
    username = app.config["ADMIN_USERNAME"]
    email = app.config["ADMIN_EMAIL"]
    password = app.config["ADMIN_PASSWORD"]
    if any(v == "CHANGE_ME" or not v for v in (username, email, password)):
        print("Admin setup skipped: set ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD in .env")
        return
    existing = query("SELECT id FROM admins WHERE username=%s OR email=%s", (username, email), one=True)
    if not existing:
        query("INSERT INTO admins (username,email,password_hash) VALUES (%s,%s,%s)",
              (username, email, generate_password_hash(password)), write=True)
        print(f"Initial admin created for {username}")


@app.context_processor
def inject_globals():
    unread = 0
    user = current_user()
    if user and user.get("role") == "student":
        try:
            row = query("SELECT COUNT(*) AS n FROM notifications WHERE student_id=%s AND is_read=0",
                        (user["id"],), one=True)
            unread = row["n"]
        except Error:
            pass
    return {"current_user": user, "unread_notifications": unread, "categories": CATEGORIES}


@app.route("/")
def index():
    try:
        events = query("SELECT * FROM events WHERE event_date >= NOW() ORDER BY event_date LIMIT 3")
    except Error:
        events = []
    return render_template("index.html", events=events)


@app.route("/health")
def health():
    try:
        query("SELECT 1", one=True)
        return {"status": "ok", "database": "connected"}
    except Error as exc:
        return {"status": "error", "database": str(exc)}, 503


@app.route("/media/events/<path:filename>")
def event_media(filename):
    if os.path.basename(filename) != filename:
        abort(404)
    if not query("SELECT 1 AS ok FROM events WHERE banner=%s", (filename,), one=True):
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/media/<path:filename>")
@login_required()
def media(filename):
    if os.path.basename(filename) != filename or not can_access_upload(filename):
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


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
                    query("""INSERT INTO students (full_name,username,email,department,student_id,password_hash)
                             VALUES (%s,%s,%s,%s,%s,%s)""",
                          (name, username, email, department, student_id,
                           generate_password_hash(password)), write=True)
                    flash("Registration successful. You can now log in.", "success")
                    return redirect(url_for("login"))
                except Error as exc:
                    if exc.errno == 1062:
                        flash("That username, email or student ID is already registered.", "danger")
                    else:
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
            table = "admins" if role == "admin" else "students"
            try:
                user = query(f"SELECT * FROM {table} WHERE username=%s OR email=%s",
                             (identity, identity), one=True)
            except Error:
                flash("Database is not available yet. Please try again later.", "danger")
                user = None
            if user and check_password_hash(user["password_hash"], password):
                if role == "student" and not user["is_active"]:
                    flash("Your student account is inactive. Contact the campus administrator.", "danger")
                else:
                    clear_login_failures(key)
                    session.clear()
                    session.permanent = True
                    session["user"] = {"id": user["id"],
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


@app.route("/student")
@login_required("student")
def student_dashboard():
    sid = current_user()["id"]
    stats = query("""SELECT COUNT(*) total,
        SUM(status='Pending') pending, SUM(status='In Progress') progress,
        SUM(status='Resolved') resolved FROM complaints WHERE student_id=%s""", (sid,), one=True)
    joined = query("SELECT COUNT(*) n FROM event_registrations WHERE student_id=%s", (sid,), one=True)["n"]
    votes = query("SELECT COUNT(*) n FROM post_votes WHERE student_id=%s", (sid,), one=True)["n"]
    recent = query("SELECT * FROM complaints WHERE student_id=%s ORDER BY created_at DESC LIMIT 5", (sid,))
    return render_template("student_dashboard.html", stats=stats, joined=joined, votes=votes, recent=recent)


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
                query("""INSERT INTO complaints (student_id,title,category,description,location,image)
                         VALUES (%s,%s,%s,%s,%s,%s)""",
                      (sid, title, category, description, location, image), write=True)
                flash("Your complaint has been submitted.", "success")
                return redirect(url_for("complaints"))
            except (ValueError, Error) as exc:
                flash(str(exc) if isinstance(exc, ValueError) else "Could not save complaint. Check database setup.", "danger")
    search = request.args.get("q", "").strip()
    term = like_term(search)
    rows = query("""SELECT * FROM complaints WHERE student_id=%s AND
        (title LIKE %s OR category LIKE %s OR status LIKE %s) ORDER BY created_at DESC""",
        (sid, term, term, term))
    return render_template("complaints.html", rows=rows, search=search)


@app.route("/complaints/<int:cid>")
@login_required()
def complaint_details(cid):
    row = query("""SELECT c.*,s.full_name FROM complaints c JOIN students s ON s.id=c.student_id
                   WHERE c.id=%s""", (cid,), one=True)
    if not row:
        abort(404)
    if current_user()["role"] == "student" and row["student_id"] != current_user()["id"]:
        abort(403)
    updates = query("""SELECT cu.*,a.username admin_name FROM complaint_updates cu
                       LEFT JOIN admins a ON a.id=cu.admin_id
                       WHERE complaint_id=%s ORDER BY cu.created_at DESC""", (cid,))
    return render_template("complaint_details.html", row=row, updates=updates)


@app.route("/admin/complaints/<int:cid>/update", methods=["POST"])
@login_required("admin")
def update_complaint(cid):
    row = query("SELECT * FROM complaints WHERE id=%s", (cid,), one=True)
    if not row:
        abort(404)
    status = request.form.get("status")
    if status not in STATUSES:
        abort(400)
    response = request.form.get("response", "").strip()
    query("UPDATE complaints SET status=%s,admin_response=%s WHERE id=%s", (status, response, cid), write=True)
    query("INSERT INTO complaint_updates (complaint_id,admin_id,status,response) VALUES (%s,%s,%s,%s)",
          (cid, current_user()["id"], status, response), write=True)
    notify(row["student_id"], "Complaint updated", f"Complaint #{cid} status: {status}. {response}",
           url_for("complaint_details", cid=cid))
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
                query("""INSERT INTO lost_found (student_id,report_type,item_name,description,location,item_date,image)
                         VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                      (current_user()["id"], report_type, item_name, description, location, item_date, image),
                      write=True)
                flash("Your item report has been posted.", "success")
                return redirect(url_for("lost_found"))
            except (ValueError, Error) as exc:
                flash(str(exc) if isinstance(exc, ValueError) else "Could not save report.", "danger")
    q = request.args.get("q", "").strip()
    term = like_term(q)
    rows = query("""SELECT lf.*,s.full_name FROM lost_found lf JOIN students s ON s.id=lf.student_id
                    WHERE (lf.item_name LIKE %s OR lf.description LIKE %s OR lf.location LIKE %s)
                    ORDER BY lf.created_at DESC""", (term, term, term))
    return render_template("lost_found.html", rows=rows, search=q)


@app.route("/lost-found/<int:item_id>/status", methods=["POST"])
@login_required("student")
def item_status(item_id):
    row = query("SELECT * FROM lost_found WHERE id=%s", (item_id,), one=True)
    if not row:
        abort(404)
    if row["student_id"] != current_user()["id"]:
        abort(403)
    status = request.form.get("status")
    if status not in ["Open", "Claimed", "Closed"]:
        abort(400)
    query("UPDATE lost_found SET status=%s WHERE id=%s", (status, item_id), write=True)
    return redirect(url_for("lost_found"))


@app.route("/lost-found/<int:item_id>/contact", methods=["POST"])
@login_required("student")
def item_contact(item_id):
    row = query("""SELECT lf.student_id,s.full_name,s.email FROM lost_found lf
                   JOIN students s ON s.id=lf.student_id WHERE lf.id=%s""", (item_id,), one=True)
    if not row:
        abort(404)
    if row["student_id"] == current_user()["id"]:
        flash("This is your own report.", "info")
    else:
        flash(f"Contact {row['full_name']}: {row['email']}", "info")
    return redirect(url_for("lost_found"))


@app.route("/events")
@login_required("student")
def events():
    rows = query("""SELECT e.*, (SELECT COUNT(*) FROM event_registrations r WHERE r.event_id=e.id) attendees,
       EXISTS(SELECT 1 FROM event_registrations r WHERE r.event_id=e.id AND r.student_id=%s) joined
       FROM events e ORDER BY e.event_date""", (current_user()["id"],))
    return render_template("events.html", rows=rows)


@app.route("/events/<int:eid>/join", methods=["POST"])
@login_required("student")
def join_event(eid):
    event = query("SELECT id FROM events WHERE id=%s AND event_date >= NOW()", (eid,), one=True)
    if not event:
        abort(400)
    try:
        query("INSERT INTO event_registrations (event_id,student_id) VALUES (%s,%s)",
              (eid, current_user()["id"]), write=True)
        flash("You joined the event.", "success")
    except Error:
        flash("You may already be registered for this event.", "warning")
    return redirect(url_for("events"))


@app.route("/events/<int:eid>/cancel", methods=["POST"])
@login_required("student")
def cancel_event(eid):
    query("DELETE FROM event_registrations WHERE event_id=%s AND student_id=%s",
          (eid, current_user()["id"]), write=True)
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
                query("INSERT INTO posts (student_id,title,body,image) VALUES (%s,%s,%s,%s)",
                      (current_user()["id"], title, body, image), write=True)
                flash("Post submitted for admin approval.", "success")
                return redirect(url_for("discussions"))
            except (ValueError, Error) as exc:
                flash(str(exc) if isinstance(exc, ValueError) else "Could not create post.", "danger")
    q = request.args.get("q", "").strip()
    term = like_term(q)
    rows = query("""SELECT p.*,s.full_name,
       (SELECT COUNT(*) FROM post_votes v WHERE v.post_id=p.id AND v.vote_type='Like') likes,
       (SELECT COUNT(*) FROM post_votes v WHERE v.post_id=p.id AND v.vote_type='Upvote') upvotes,
       (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comment_count
       FROM posts p JOIN students s ON s.id=p.student_id
       WHERE p.status='Approved' AND (p.title LIKE %s OR p.body LIKE %s) ORDER BY p.created_at DESC""",
       (term, term))
    return render_template("discussions.html", rows=rows, search=q)


@app.route("/posts/<int:pid>/comment", methods=["POST"])
@login_required("student")
def comment(pid):
    post = query("SELECT id FROM posts WHERE id=%s AND status='Approved'", (pid,), one=True)
    if not post:
        abort(404)
    body = request.form.get("body", "").strip()
    if body:
        query("INSERT INTO comments (post_id,student_id,body) VALUES (%s,%s,%s)",
              (pid, current_user()["id"], body), write=True)
    return redirect(url_for("discussions"))


@app.route("/posts/<int:pid>/vote/<vote_type>", methods=["POST"])
@login_required("student")
def vote(pid, vote_type):
    if vote_type not in ["Like", "Upvote"]:
        abort(400)
    post = query("SELECT id FROM posts WHERE id=%s AND status='Approved'", (pid,), one=True)
    if not post:
        abort(404)
    try:
        query("INSERT INTO post_votes (post_id,student_id,vote_type) VALUES (%s,%s,%s)",
              (pid, current_user()["id"], vote_type), write=True)
        flash(f"{vote_type} recorded.", "success")
    except Error:
        flash(f"You already gave this {vote_type.lower()}.", "info")
    return redirect(url_for("discussions"))


@app.route("/posts/<int:pid>/report", methods=["POST"])
@login_required("student")
def report_post(pid):
    post = query("SELECT id FROM posts WHERE id=%s AND status='Approved'", (pid,), one=True)
    if not post:
        abort(404)
    reason = request.form.get("reason", "").strip()[:255]
    try:
        query("INSERT INTO post_reports (post_id,student_id,reason) VALUES (%s,%s,%s)",
              (pid, current_user()["id"], reason), write=True)
        flash("Report submitted for admin review.", "info")
    except Error:
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
                    query("UPDATE students SET full_name=%s,department=%s,student_id=%s WHERE id=%s",
                          (name, department, student_id, sid), write=True)
                    session["user"]["name"] = name
                    flash("Profile updated.", "success")
                except Error:
                    flash("That student ID is already in use.", "danger")
        elif action == "password":
            row = query("SELECT password_hash FROM students WHERE id=%s", (sid,), one=True)
            if not check_password_hash(row["password_hash"], request.form.get("current_password", "")):
                flash("Current password is incorrect.", "danger")
            elif len(request.form.get("new_password", "")) < 8:
                flash("New password must be at least 8 characters.", "danger")
            else:
                query("UPDATE students SET password_hash=%s WHERE id=%s",
                      (generate_password_hash(request.form["new_password"]), sid), write=True)
                flash("Password changed.", "success")
        return redirect(url_for("profile"))
    row = query("SELECT * FROM students WHERE id=%s", (sid,), one=True)
    return render_template("profile.html", row=row)


@app.route("/notifications")
@login_required("student")
def notifications():
    rows = query("SELECT * FROM notifications WHERE student_id=%s ORDER BY created_at DESC",
                 (current_user()["id"],))
    return render_template("notifications.html", rows=rows)


@app.route("/notifications/read", methods=["POST"])
@login_required("student")
def notifications_read():
    query("UPDATE notifications SET is_read=1 WHERE student_id=%s", (current_user()["id"],), write=True)
    flash("All notifications marked as read.", "info")
    return redirect(url_for("notifications"))


@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    stats = {
        "students": query("SELECT COUNT(*) n FROM students", one=True)["n"],
        "complaints": query("SELECT COUNT(*) n FROM complaints", one=True)["n"],
        "pending": query("SELECT COUNT(*) n FROM complaints WHERE status='Pending'", one=True)["n"],
        "resolved": query("SELECT COUNT(*) n FROM complaints WHERE status='Resolved'", one=True)["n"],
        "posts": query("SELECT COUNT(*) n FROM posts", one=True)["n"],
        "events": query("SELECT COUNT(*) n FROM events", one=True)["n"]
    }
    complaints_rows = query("""SELECT c.*,s.full_name FROM complaints c JOIN students s ON s.id=c.student_id
                               ORDER BY c.created_at DESC LIMIT 10""")
    students = query("SELECT * FROM students ORDER BY created_at DESC LIMIT 8")
    monthly = query("""SELECT DATE_FORMAT(created_at,'%b %Y') label,COUNT(*) total FROM complaints
                       GROUP BY DATE_FORMAT(created_at,'%Y-%m'),DATE_FORMAT(created_at,'%b %Y')
                       ORDER BY DATE_FORMAT(created_at,'%Y-%m') LIMIT 12""")
    dept = query("""SELECT COALESCE(s.department,'Unspecified') label,COUNT(*) total FROM complaints c
                    JOIN students s ON s.id=c.student_id GROUP BY s.department ORDER BY total DESC LIMIT 8""")
    return render_template("admin_dashboard.html", stats=stats, complaints=complaints_rows,
                           students=students, monthly=monthly, dept=dept)


@app.route("/admin/students")
@login_required("admin")
def manage_students():
    q = request.args.get("q", "").strip()
    term = like_term(q)
    rows = query("""SELECT * FROM students WHERE full_name LIKE %s OR username LIKE %s OR email LIKE %s
                    ORDER BY created_at DESC""", (term, term, term))
    return render_template("admin_students.html", rows=rows, search=q)


@app.route("/admin/students/<int:sid>/toggle", methods=["POST"])
@login_required("admin")
def toggle_student(sid):
    query("UPDATE students SET is_active=1-is_active WHERE id=%s", (sid,), write=True)
    flash("Student status updated.", "success")
    return redirect(url_for("manage_students"))


@app.route("/admin/posts")
@login_required("admin")
def manage_posts():
    rows = query("""SELECT p.*,s.full_name FROM posts p JOIN students s ON s.id=p.student_id
                    ORDER BY p.created_at DESC""")
    return render_template("admin_posts.html", rows=rows)


@app.route("/admin/posts/<int:pid>/<action>", methods=["POST"])
@login_required("admin")
def moderate_post(pid, action):
    row = query("SELECT image FROM posts WHERE id=%s", (pid,), one=True)
    if not row:
        abort(404)
    status = {"approve": "Approved", "reject": "Rejected"}.get(action)
    if status:
        query("UPDATE posts SET status=%s WHERE id=%s", (status, pid), write=True)
    elif action == "delete":
        query("DELETE FROM posts WHERE id=%s", (pid,), write=True)
        delete_upload(row["image"])
    else:
        abort(400)
    return redirect(url_for("manage_posts"))


@app.route("/admin/reports")
@login_required("admin")
def admin_reports():
    rows = query("""SELECT pr.id,pr.reason,pr.created_at,p.id post_id,p.title post_title,
                    s.full_name reporter FROM post_reports pr
                    JOIN posts p ON p.id=pr.post_id JOIN students s ON s.id=pr.student_id
                    ORDER BY pr.created_at DESC""")
    return render_template("admin_reports.html", rows=rows)


@app.route("/admin/reports/<int:rid>/dismiss", methods=["POST"])
@login_required("admin")
def dismiss_report(rid):
    query("DELETE FROM post_reports WHERE id=%s", (rid,), write=True)
    flash("Report dismissed.", "info")
    return redirect(url_for("admin_reports"))


@app.route("/admin/reports/<int:rid>/takedown", methods=["POST"])
@login_required("admin")
def takedown_report(rid):
    report = query("SELECT post_id FROM post_reports WHERE id=%s", (rid,), one=True)
    if not report:
        abort(404)
    query("UPDATE posts SET status='Pending' WHERE id=%s", (report["post_id"],), write=True)
    query("DELETE FROM post_reports WHERE post_id=%s", (report["post_id"],), write=True)
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
                banner = save_upload("banner")
                query("""INSERT INTO events (title,description,venue,event_date,banner,created_by)
                         VALUES (%s,%s,%s,%s,%s,%s)""",
                      (title, description, venue, event_date, banner, current_user()["id"]), write=True)
                flash("Event created.", "success")
                return redirect(url_for("manage_events"))
            except (ValueError, Error) as exc:
                flash(str(exc) if isinstance(exc, ValueError) else "Could not create event.", "danger")
    rows = query("SELECT * FROM events ORDER BY event_date DESC")
    return render_template("admin_events.html", rows=rows)


@app.route("/admin/events/<int:eid>/delete", methods=["POST"])
@login_required("admin")
def delete_event(eid):
    row = query("SELECT banner FROM events WHERE id=%s", (eid,), one=True)
    if not row:
        abort(404)
    query("DELETE FROM events WHERE id=%s", (eid,), write=True)
    delete_upload(row["banner"])
    return redirect(url_for("manage_events"))


@app.route("/admin/events/<int:eid>/registrations")
@login_required("admin")
def event_registrations(eid):
    event = query("SELECT * FROM events WHERE id=%s", (eid,), one=True)
    if not event:
        abort(404)
    rows = query("""SELECT s.full_name,s.username,s.email,s.department,r.registered_at
                    FROM event_registrations r JOIN students s ON s.id=r.student_id
                    WHERE r.event_id=%s ORDER BY r.registered_at""", (eid,))
    return render_template("admin_registrations.html", event=event, rows=rows)


@app.route("/admin/lost-found")
@login_required("admin")
def admin_lost_found():
    rows = query("""SELECT lf.*,s.full_name FROM lost_found lf JOIN students s ON s.id=lf.student_id
                    ORDER BY lf.created_at DESC""")
    return render_template("admin_lost_found.html", rows=rows)


@app.route("/admin/lost-found/<int:item_id>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_item(item_id):
    row = query("SELECT image FROM lost_found WHERE id=%s", (item_id,), one=True)
    if not row:
        abort(404)
    query("DELETE FROM lost_found WHERE id=%s", (item_id,), write=True)
    delete_upload(row["image"])
    return redirect(url_for("admin_lost_found"))


@app.route("/admin/analytics")
@login_required("admin")
def analytics():
    status = query("SELECT status label,COUNT(*) total FROM complaints GROUP BY status")
    monthly = query("""SELECT DATE_FORMAT(created_at,'%b %Y') label,COUNT(*) total FROM complaints
                       GROUP BY DATE_FORMAT(created_at,'%Y-%m'),DATE_FORMAT(created_at,'%b %Y')
                       ORDER BY DATE_FORMAT(created_at,'%Y-%m')""")
    dept = query("""SELECT COALESCE(s.department,'Unspecified') label,COUNT(*) total FROM complaints c
                    JOIN students s ON s.id=c.student_id GROUP BY s.department ORDER BY total DESC""")
    participation = query("""SELECT e.title label,COUNT(r.id) total FROM events e
                             LEFT JOIN event_registrations r ON r.event_id=e.id
                             GROUP BY e.id,e.title ORDER BY total DESC LIMIT 10""")
    registrations = query("""SELECT DATE_FORMAT(created_at,'%b %Y') label,COUNT(*) total FROM students
                             GROUP BY DATE_FORMAT(created_at,'%Y-%m'),DATE_FORMAT(created_at,'%b %Y')
                             ORDER BY DATE_FORMAT(created_at,'%Y-%m')""")
    return render_template("analytics.html", status=status, monthly=monthly, dept=dept,
                           participation=participation, registrations=registrations)


@app.route("/admin/settings")
@login_required("admin")
def settings():
    return render_template("admin_settings.html")


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


# Runs on import too, so WSGI deployments get the initial admin as documented.
try:
    ensure_admin()
except Exception as exc:  # Database may be unreachable on serverless hosts.
    print("Admin setup unavailable:", exc)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
