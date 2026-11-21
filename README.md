# Zain University – Campus Connect

A Flask + MongoDB (Atlas) university campus portal with separate student and administrator access.

## Features
- Student registration/login, profile editing and password changes
- Complaint submission, image uploads, status history and admin responses
- Lost & Found reports with owner contact information
- Campus events, registrations and cancellation
- Moderated student discussions, comments, likes and upvotes, with admin report review
- Notifications for complaint status updates
- Admin student management, moderation, event management and analytics
- Chart.js dashboards calculated from MongoDB aggregation results
- CSRF protection, password hashing, role checks and upload validation

## Requirements
- Python 3.10+
- A MongoDB database (MongoDB Atlas free tier recommended, or a local MongoDB 7+)
- VS Code (recommended)

## Setup in VS Code

1. Extract the ZIP and open the `zain-university` folder in VS Code.
2. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```
3. Activate it:
   - Windows PowerShell: `.\.venv\Scripts\Activate.ps1`
   - macOS/Linux: `source .venv/bin/activate`
4. Install packages:
   ```bash
   pip install -r requirements.txt
   ```
5. Create the collections and indexes in MongoDB (idempotent):
   ```bash
   python mongo_init.py
   ```
6. Copy `.env.example` to `.env` and fill in your MongoDB connection string, admin account and a long random Flask secret:
   ```env
   FLASK_SECRET_KEY=use-a-long-random-secret
   MONGODB_URI=mongodb+srv://USER:PASSWORD@HOST/DATABASE?retryWrites=true&w=majority
   MONGODB_DB=zain_university
   ADMIN_USERNAME=your_admin_username
   ADMIN_EMAIL=your_admin_email
   ADMIN_PASSWORD=your_strong_admin_password
   ```
7. Start the website:
   ```bash
   python app.py
   ```
8. Open `http://127.0.0.1:5000`.

The first run creates the configured administrator if the credentials are set and the database is available. The setup is idempotent: it does not overwrite an existing admin account.

## Admin setup
Set `ADMIN_USERNAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` in `.env` before the first run. Never put `.env` in GitHub. Admin registration is not exposed publicly. The admin password is hashed before storage.

## Uploads
Images are restricted to PNG, JPG, JPEG, GIF and WEBP and a maximum request size of 5 MB. File signatures are verified, filenames are random, and files are stored in `uploads/` (outside `static/`). Complaint, Lost & Found and post images are served through an authenticated `/media/<filename>` route that only allows the owner or an admin. Event banners are public through `/media/events/<filename>`. For a production deployment, configure private/object storage and malware scanning.

## Database
`mongo_init.py` creates the collections and indexes used by the app in the database named by `MONGODB_DB`. The connection string is read from `MONGODB_URI` in `.env` and is also created automatically on first start.

## Security and production notes
- Flask-WTF CSRF protection is enabled on all forms; logout and "mark notifications read" are POST-only.
- Passwords use Werkzeug's secure password hashing; emails are validated on registration.
- All data access goes through PyMongo with filtered queries; search terms are regex-escaped.
- Admin and student routes are role-protected, and account deactivation takes effect immediately on the next request.
- Login attempts are throttled per IP/identity (5 failures per 10 minutes in a single process).
- Debug mode is off by default (`FLASK_DEBUG=1` enables it locally only). Sessions use HttpOnly, SameSite=Lax cookies; set `SESSION_COOKIE_SECURE=1` behind HTTPS.
- Change `FLASK_SECRET_KEY` before use; the app generates a random one if the configured value is missing or weak.
- Use HTTPS, verified email/password reset delivery, backups, a rate-limit proxy/service for multi-worker deployments, and a production WSGI server before public deployment.
- The password reset feature is not enabled in this offline starter because a secure reset requires an email delivery provider and verified identity flow. Do not implement insecure reset links without one.

## Troubleshooting
- `Authentication failed`: check the username/password inside `MONGODB_URI` in `.env`.
- `IP not allowed`: add your IP (or `0.0.0.0/0`) to the MongoDB Atlas Network Access list.
- `ModuleNotFoundError`: activate `.venv` and run `pip install -r requirements.txt`.
- `Server selection timed out`: check your internet connection and the Atlas cluster status.
- `/health` returns database status as JSON.

## Routes
- `/` public landing page, `/health` database status
- `/register`, `/login`, `/logout` (POST)
- `/student`, `/complaints`, `/lost-found`, `/events`, `/discussions`, `/profile`, `/notifications`, `/notifications/read` (POST)
- `/media/<filename>` (authenticated images), `/media/events/<filename>` (public banners)
- `/admin`, `/admin/students`, `/admin/posts`, `/admin/reports`, `/admin/events`, `/admin/lost-found`, `/admin/analytics`, `/admin/settings`

## Smoke test
After setting up the database and `.env`, run `python smoke_test.py` from the project folder. It exercises registration, login, role checks, uploads, protected media, event creation and admin pages using a temporary student account, then removes the test data.
