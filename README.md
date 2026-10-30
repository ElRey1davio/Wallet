# Wallet API

A mini wallet JSON API built to learn backend fundamentals. Users can register, log in with a password or GitHub, start a deposit through a payment provider, withdraw with a PIN, check their balance and view their transaction history.

**Stack:** Python, Flask, psycopg2, PostgreSQL (Neon), JWT, Flask-Limiter. Tested with Postman.

## Features

- Register and log in with email and password (hashed passwords and PINs, 30-minute JWT)
- Sign in with GitHub (OAuth with a `state` check, verified primary email only)
- Deposit flow modelled on real payment providers: initiate a pending deposit, then a webhook confirms it
- Withdrawals protected by a PIN, with the balance check and spend done in one atomic `UPDATE`
- Webhook protected by a secret header and safe against duplicate delivery (idempotent)
- Rate limiting on sensitive routes
- Paginated transaction history with an index for fast queries
- Request and event logging to `wallet.log` (never passwords, PINs, tokens or secrets)

## Setup

1. Clone the repo and create a virtual environment:

   ```powershell
   git clone https://github.com/ElRey1davio/Wallet.git
   cd Wallet
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. Create a PostgreSQL database (a free Neon project works) and the tables below.

3. Create a `.env` file in the project root (it is git-ignored):

   | Variable | What it is |
   |---|---|
   | `DATABASE_URL` | PostgreSQL connection string |
   | `SECRET_KEY` | Random string used to sign JWTs and the session cookie |
   | `PAYMENT_LINK` | Base URL of the payment page returned on deposit |
   | `WEBHOOK_SECRET` | Shared secret the payment provider sends in `X-Webhook-Secret` |
   | `GITHUB_CLIENT_ID` | From your GitHub OAuth App |
   | `GITHUB_CLIENT_SECRET` | From your GitHub OAuth App |
   | `GITHUB_REDIRECT_URI` | `http://127.0.0.1:5000/auth/github/callback` |

   Generate a random value for `SECRET_KEY` and `WEBHOOK_SECRET` with:

   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

4. Run the app:

   ```powershell
   python app.py
   ```

   The API runs at `http://127.0.0.1:5000`.

### GitHub OAuth App

In GitHub go to Settings, Developer settings, OAuth Apps, New OAuth App. Set the homepage URL to `http://127.0.0.1:5000` and the authorization callback URL to `http://127.0.0.1:5000/auth/github/callback`. Use `127.0.0.1` everywhere, not `localhost`.

## Database schema (reference)

```sql
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,          -- empty for GitHub users
    pin_hash TEXT,               -- empty until a PIN is set
    balance NUMERIC(12,2) NOT NULL DEFAULT 0
);

CREATE TABLE transactions (
    transaction_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(user_id),
    type TEXT NOT NULL,          -- 'deposit' or 'withdrawal'
    amount NUMERIC(12,2) NOT NULL,
    reference TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_transactions_user_created
    ON transactions (user_id, created_at DESC);
```

## Endpoints

All responses are JSON with `status` and `message` (or data). Protected routes need the header `Authorization: Bearer <token>`.

| Method | Route | Auth | Purpose |
|---|---|---|---|
| POST | `/register` | none | Create a user (name, email, password, 4-digit pin) |
| POST | `/login` | none | Log in with email and password, returns a JWT |
| GET | `/auth/github` | none | Start GitHub sign-in (open in a browser) |
| GET | `/auth/github/callback` | none | GitHub returns here, responds with a JWT |
| GET | `/balance` | Bearer | Current balance |
| POST | `/deposit/initiate` | Bearer | Start a deposit, returns a reference and payment link |
| POST | `/webhook/payment` | `X-Webhook-Secret` | Provider confirms or fails a payment |
| POST | `/withdraw` | Bearer | Withdraw with amount and pin |
| GET | `/transactions` | Bearer | History, supports `?page=` and `?limit=` (default 10, max 100) |

### Example requests

Register:

```json
POST /register
{ "name": "Ada", "email": "ada@test.com", "password": "a-strong-password", "pin": "1234" }
```

Log in:

```json
POST /login
{ "email": "ada@test.com", "password": "a-strong-password" }
```

Start a deposit:

```json
POST /deposit/initiate
{ "amount": 5000 }
```

Simulate the provider confirming it (header `X-Webhook-Secret` required):

```json
POST /webhook/payment
{ "reference": "<reference from the deposit>", "status": "success" }
```

Withdraw:

```json
POST /withdraw
{ "amount": 1000, "pin": "1234" }
```

## Design notes

- **No double spending:** `UPDATE users SET balance = balance - amount WHERE user_id = ... AND balance >= amount`, then `rowcount` is checked, so the check and the spend happen in one step.
- **No double crediting:** the webhook flips the status with `WHERE reference = ... AND status = 'pending'` and credits the balance only if one row changed. A duplicate webhook, even one arriving at the same instant, credits once, and still gets a 200 so the provider stops retrying.
- **Money:** `NUMERIC` in the database and `Decimal` in Python, never float.
- **Auth:** wrong email and wrong password return the same 401 so the API does not reveal which emails exist.
- **GitHub sign-in:** a random `state` stops forged callbacks, the client secret never leaves the server, and only a verified primary email is trusted. The user gets the app's own JWT.
- **Rate limiting:** 5 per minute on `/register`, `/login` and `/withdraw` (`/withdraw` is keyed per user, with IP as a fallback). Counters are in memory, so production should use Redis.

## Known limitations and next steps

- Add `POST /set-pin` (only while no PIN is set) and `POST /set-password` so GitHub users can set up a PIN and a password
- A real withdrawal destination (bank payout)
- Google sign-in
- Lockout after repeated wrong PINs, with OTP verification to unlock
- Webhook signature verification (HMAC with a timestamp) instead of a shared secret header
