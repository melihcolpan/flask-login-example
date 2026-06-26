# Flask Login Example

A small, beginner-friendly example of **token-based authentication** with
[Flask](https://flask.palletsprojects.com/). It uses Flask **blueprints**, a
clean app **factory**, request **rate limiting**, and role-based access — a nice
next step after a "hello world" Flask app.

You register users, log them in, receive an access token + refresh token, and
use those tokens to call protected endpoints.

---

## Features

- 🔐 **Register / Login / Logout** with JSON requests
- 🪙 **Access + refresh tokens** (signed and time-limited)
- 👮 **Role-based access** — `user`, `admin`, `super_admin`
- 🔑 **Passwords hashed with PBKDF2-SHA256** (never stored in plaintext)
- 🚦 **Rate limiting** on login via Flask-Limiter
- 🧱 Organised with a **blueprint + app factory** layout
- 🧪 A small **test suite** (`nose2`) you can run in one command

## Tech stack

| Purpose          | Library                    |
| ---------------- | -------------------------- |
| Web framework    | Flask (blueprints)         |
| Database / ORM   | Flask-SQLAlchemy + SQLite  |
| Password hashing | passlib (pbkdf2-sha256)    |
| Token signing    | itsdangerous               |
| Rate limiting    | Flask-Limiter              |
| Tests            | nose2                      |

---

## Project structure

```
flask-login-example/
├── run.py                      # App entry point
├── requirements.txt
└── api/
    ├── routes/
    │   └── routes.py           # All endpoints (register, login, ...)
    ├── database/
    │   ├── config.py           # SQLAlchemy setup
    │   └── models/
    │       ├── model_user.py   # User model + password hashing
    │       └── blacklist_model.py
    └── utils/
        ├── factory.py          # Builds the Flask app (the "app factory")
        ├── config.py           # Configuration classes
        ├── auth.py             # Token serializers + auth object
        ├── decorators.py       # @permission role checks
        └── responses.py        # Helper for consistent JSON responses
```

---

## Prerequisites

- **Python 3.8+**
- A tool to send HTTP requests: [httpie](https://httpie.io/) (used below),
  `curl`, Postman, or Insomnia.

---

## Quick start

```bash
# 1. Get the code
git clone https://github.com/melihcolpan/flask-login-example
cd flask-login-example

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set the required secrets (any random strings; generated here for you)
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
export REFRESH_JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# 5. (Optional, recommended for a first try) create ready-made demo users
export SEED_DEMO_USERS=true

# 6. Run it
python run.py
```

The API is now running at **http://localhost:5000**.

> 💡 On Windows PowerShell, use `$env:JWT_SECRET="..."` instead of `export`.

### Environment variables

| Variable             | Required | Default      | What it does                                                        |
| -------------------- | :------: | ------------ | ------------------------------------------------------------------- |
| `JWT_SECRET`         |   ✅     | –            | Signs **access** tokens. Keep it secret.                            |
| `REFRESH_JWT_SECRET` |   ✅     | –            | Signs **refresh** tokens. Keep it secret.                           |
| `SECRET_KEY`         |   ✅     | –            | Flask's secret key.                                                 |
| `APP_CONFIG`         |   ❌     | `production` | `production`, `development` (debug on), or `testing`.               |
| `SEED_DEMO_USERS`    |   ❌     | `false`      | Set to `true` to create the demo accounts listed below.             |
| `DATABASE_URI`       |   ❌     | local SQLite | Override the database connection string.                            |

The app **refuses to start** if a required secret is missing — this prevents
accidentally shipping hardcoded secrets.

### Demo accounts

These are created **only** when you run with `SEED_DEMO_USERS=true` (off by
default, so a real deployment never ships with known passwords):

| Role          | Email                     | Password         |
| ------------- | ------------------------- | ---------------- |
| Super admin   | `sa_email@example.com`    | `sa_password`    |
| Admin         | `admin_email@example.com` | `admin_password` |
| User          | `test_email@example.com`  | `test_password`  |

---

## How authentication works (the 30-second version)

1. You **register** a user, then **log in** with their email + password.
2. The server returns two tokens inside the `value` field:
   - **`access_token`** — short-lived (1 hour). Send it on every protected
     request as `Authorization: Bearer <access_token>`.
   - **`refresh_token`** — longer-lived (2 hours). Use it to get a fresh access
     token without logging in again.
3. **Logout** invalidates a refresh token by blacklisting it.

Every response has the same shape:

```json
{ "code": "test_stat", "message": "SUCCESS.", "value": { ... } }
```

---

## API reference

Base URL: `http://localhost:5000`

| Method | Endpoint                       | Auth required    | Description                                     |
| ------ | ------------------------------ | :--------------: | ----------------------------------------------- |
| POST   | `/v1.0/auth/register`          | –                | Create a new user                               |
| POST   | `/v1.0/auth/login`             | – (rate limited) | Log in, receive tokens                          |
| POST   | `/v1.0/auth/refresh`           | –                | Exchange a refresh token for a new access token |
| POST   | `/v1.0/auth/logout`            | ✅ Bearer        | Invalidate a refresh token                      |
| POST   | `/v1.0/auth/password_change`   | ✅ Bearer        | Change your password                            |
| GET    | `/v1.0/data`                   | ✅ Admin+        | Example protected route — lists users           |

> **Note on roles:** `register` always creates a normal **`user`**. The `admin`
> and `super_admin` roles come from the demo seed or are assigned directly in
> the database.

---

## Usage examples

Examples use [httpie](https://httpie.io/), with a `curl` equivalent for the
first two.

### 1. Register

```bash
http POST :5000/v1.0/auth/register \
  username=alice password=s3cret email=alice@example.com
```

```bash
# curl version
curl -X POST http://localhost:5000/v1.0/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"s3cret","email":"alice@example.com"}'
```

### 2. Login

```bash
http POST :5000/v1.0/auth/login email=alice@example.com password=s3cret
```

```bash
# curl version
curl -X POST http://localhost:5000/v1.0/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"s3cret"}'
```

Response — the tokens are under `value`:

```json
{
  "code": "test_stat",
  "message": "SUCCESS.",
  "value": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ..."
  }
}
```

### 3. Call a protected route

```bash
http GET :5000/v1.0/data Authorization:"Bearer <ACCESS_TOKEN>"
```

### 4. Refresh an expired access token

```bash
http POST :5000/v1.0/auth/refresh refresh_token=<REFRESH_TOKEN>
```

### 5. Change your password

```bash
http POST :5000/v1.0/auth/password_change \
  Authorization:"Bearer <ACCESS_TOKEN>" \
  old_pass=s3cret new_pass=ev3nm0resecret
```

### 6. Logout (invalidate a refresh token)

```bash
http POST :5000/v1.0/auth/logout \
  Authorization:"Bearer <ACCESS_TOKEN>" \
  refresh_token=<REFRESH_TOKEN>
```

---

## Running the tests

```bash
# Tests need the secret env vars and the testing config.
export JWT_SECRET=test REFRESH_JWT_SECRET=test SECRET_KEY=test
export APP_CONFIG=testing

python -m nose2 -v
```

You should see all tests pass.

---

## Security notes

This example follows a few basic good practices:

- **No hardcoded secrets** — token secrets and `SECRET_KEY` come from the
  environment, and the app won't start without them.
- **Passwords are hashed** with PBKDF2-SHA256; plaintext is never stored.
- **No default accounts by default** — demo users only exist when you opt in
  with `SEED_DEMO_USERS=true`.
- **Debug is off by default** — enable it only locally with
  `APP_CONFIG=development`.

For real production use, add HTTPS, a production WSGI server (e.g. gunicorn), a
real database (PostgreSQL), and a shared rate-limit store (e.g. Redis).

---

## License

MIT — free to use, modify, and learn from.
