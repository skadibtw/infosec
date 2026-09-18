import datetime
import html
import os
import sqlite3
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

app = Flask(__name__)
SECRET = os.environ.get("JWT_SECRET") or os.urandom(32).hex()
if len(SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be at least 32 characters")
DB = os.environ.get("DB_PATH", "app.db")


def db():
    return sqlite3.connect(DB)


def init_db():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash BLOB NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, author TEXT NOT NULL, text TEXT NOT NULL)")
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if admin_password:
            c.execute(
                "INSERT OR IGNORE INTO users VALUES (?, ?)",
                ("admin", bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt())),
            )


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        try:
            g.user = jwt.decode(token, SECRET, algorithms=["HS256"])["sub"]
        except jwt.PyJWTError:
            return jsonify(error="unauthorized"), 401
        return f(*args, **kwargs)

    return wrapper


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username and password required"), 400
    with db() as c:
        row = c.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not bcrypt.checkpw(password.encode(), row[0]):
        return jsonify(error="invalid credentials"), 401
    exp = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    return jsonify(token=jwt.encode({"sub": username, "exp": exp}, SECRET, algorithm="HS256"))


@app.get("/api/data")
@auth_required
def get_data():
    with db() as c:
        rows = c.execute("SELECT id, author, text FROM posts").fetchall()
    return jsonify([{"id": i, "author": html.escape(a), "text": html.escape(t)} for i, a, t in rows])


@app.post("/api/posts")
@auth_required
def create_post():
    text = (request.get_json(silent=True) or {}).get("text")
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="text required"), 400
    with db() as c:
        post_id = c.execute("INSERT INTO posts (author, text) VALUES (?, ?)", (g.user, text)).lastrowid
    return jsonify(id=post_id, author=html.escape(g.user), text=html.escape(text)), 201


init_db()

if __name__ == "__main__":
    app.run()
