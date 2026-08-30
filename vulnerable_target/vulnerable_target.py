# -*- coding: utf-8 -*-
"""
ProbeX – Vulnerable Test Target
================================
A deliberately insecure Flask application for testing ProbeX locally.

VULNERABILITIES PRESENT (by design):
  1.  Reflected XSS              – /search?q=<script>alert(1)</script>
  2.  SQL Injection (error)      – /user?id=1' OR '1'='1
  3.  SQL Injection (time-blind) – /login  (username field)
  4.  Missing security headers   – no CSP, X-Frame-Options, HSTS
  5.  Open redirect              – /redirect?next=https://evil.example.com
  6.  Path traversal             – /file?name=../../etc/passwd
  7.  Sensitive data exposure    – /api/config exposes API keys
  8.  SSRF                       – /fetch?url=http://internal/
  9.  SSTI (Jinja2)              – /greet?name={{7*7}}

WARNING: DO NOT deploy this on a public server.
Run only on localhost for local ProbeX testing.

Usage:
    pip install flask
    python vulnerable_target.py
    # Runs on http://localhost:5500
"""

import os
import sqlite3
import subprocess
import urllib.request
from flask import Flask, request, render_template_string, redirect, jsonify, Response

app = Flask(__name__)

# ─── Database setup ──────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_target.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    """)
    c.executemany("INSERT OR IGNORE INTO users VALUES (?,?,?,?,?)", [
        (1, 'admin',    'admin123',    'admin@vuln.local',   'admin'),
        (2, 'alice',    'password1',   'alice@vuln.local',   'user'),
        (3, 'bob',      'qwerty',      'bob@vuln.local',     'user'),
        (4, 'charlie',  'letmein',     'charlie@vuln.local', 'user'),
    ])
    c.executemany("INSERT OR IGNORE INTO products VALUES (?,?,?,?)", [
        (1, 'Widget A', 9.99,  'A basic widget'),
        (2, 'Widget B', 19.99, 'A premium widget'),
        (3, 'Widget C', 4.99,  'A cheap widget'),
    ])
    conn.commit()
    conn.close()

# ─── Base HTML template ───────────────────────────────────────────────────────

BASE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnShop – {title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, sans-serif; background: #f9f9f7; color: #1a1a1a; }}
  nav {{ background: #1e3a5f; color: white; padding: 12px 24px; display: flex; gap: 16px; align-items: center; }}
  nav a {{ color: #90cdf4; text-decoration: none; font-size: 14px; }}
  nav a:hover {{ color: white; }}
  .logo {{ font-weight: 700; color: white; margin-right: auto; }}
  main {{ max-width: 960px; margin: 32px auto; padding: 0 24px; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 16px; }}
  .card {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
  input, button {{ padding: 8px 12px; border-radius: 6px; border: 1px solid #cbd5e0; font-size: 14px; }}
  button {{ background: #1e3a5f; color: white; border: none; cursor: pointer; }}
  button:hover {{ background: #2c5282; }}
  .result {{ margin-top: 12px; padding: 12px; background: #ebf8ff; border-radius: 6px; font-size: 14px; }}
  .error {{ background: #fff5f5; color: #c53030; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e2e8f0; }}
  th {{ background: #f7fafc; font-weight: 600; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 99px; font-size: 11px; font-weight: 600; }}
  .badge-admin {{ background: #fed7d7; color: #c53030; }}
  .badge-user  {{ background: #e9d8fd; color: #6b46c1; }}
</style>
</head>
<body>
<nav>
  <span class="logo">🛒 VulnShop</span>
  <a href="/">Home</a>
  <a href="/search">Search</a>
  <a href="/products">Products</a>
  <a href="/login">Login</a>
  <a href="/greet">Greet</a>
  <a href="/api/config">Config API</a>
</nav>
<main>
{content}
</main>
</body>
</html>"""

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    content = """
    <h1>Welcome to VulnShop</h1>
    <div class="card">
      <p style="margin-bottom:12px;color:#555;">A deliberately vulnerable demo shop for security testing with ProbeX.</p>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:16px;">
        <a href="/search?q=shoes" style="display:block;padding:12px;background:#ebf8ff;border-radius:8px;text-decoration:none;color:#1e3a5f;">🔍 Search products</a>
        <a href="/user?id=1" style="display:block;padding:12px;background:#f0fff4;border-radius:8px;text-decoration:none;color:#276749;">👤 View user profile</a>
        <a href="/products" style="display:block;padding:12px;background:#fffff0;border-radius:8px;text-decoration:none;color:#744210;">📦 Product catalogue</a>
      </div>
    </div>
    <div class="card">
      <h2 style="margin-bottom:8px;font-size:1rem;">Vulnerability Index</h2>
      <table>
        <tr><th>Type</th><th>Endpoint</th><th>Parameter</th></tr>
        <tr><td>Reflected XSS</td><td>/search</td><td>q</td></tr>
        <tr><td>SQL Injection (error)</td><td>/user</td><td>id</td></tr>
        <tr><td>SQL Injection (login)</td><td>/login</td><td>username, password</td></tr>
        <tr><td>Open Redirect</td><td>/redirect</td><td>next</td></tr>
        <tr><td>Path Traversal</td><td>/file</td><td>name</td></tr>
        <tr><td>Sensitive Exposure</td><td>/api/config</td><td>—</td></tr>
        <tr><td>SSRF</td><td>/fetch</td><td>url</td></tr>
        <tr><td>SSTI</td><td>/greet</td><td>name</td></tr>
        <tr><td>Missing Headers</td><td>All routes</td><td>—</td></tr>
      </table>
    </div>
    """
    return render_template_string(BASE.format(title="Home", content=content))


# ── 1. Reflected XSS ──────────────────────────────────────────────────────────

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # Safe parameterized query — XSS is in the HTML output below, not SQLi
        c.execute("SELECT name, price, description FROM products WHERE name LIKE ?", (f"%{q}%",))
        rows = c.fetchall()
    except Exception as e:
        rows = []
    conn.close()

    rows_html = "".join(
        f"<tr><td>{r[0]}</td><td>${r[1]:.2f}</td><td>{r[2]}</td></tr>" for r in rows
    ) if rows else "<tr><td colspan=3 style='color:#999'>No results found.</td></tr>"

    # VULNERABLE: q is injected directly into HTML — Reflected XSS
    content = f"""
    <h1>Search Products</h1>
    <div class="card">
      <form action="/search" method="get">
        <input name="q" value="{q}" placeholder="Search…" style="width:300px;margin-right:8px;">
        <button type="submit">Search</button>
      </form>
      <div class="result">
        Showing results for: <b>{q}</b>
      </div>
      <table style="margin-top:12px;">
        <tr><th>Name</th><th>Price</th><th>Description</th></tr>
        {rows_html}
      </table>
    </div>
    """
    # NOTE: Returned without escaping q — this is the intentional XSS sink
    return BASE.format(title="Search", content=content)


# ── 2. SQL Injection (error-based) ────────────────────────────────────────────

@app.route("/user")
def user():
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # VULNERABLE: direct string interpolation — SQL Injection
    try:
        c.execute(f"SELECT id, username, email, role FROM users WHERE id = {user_id}")
        row = c.fetchone()
        if row:
            badge = f'<span class="badge badge-{row[3]}">{row[3]}</span>'
            result_html = f"""
            <table>
              <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
              <tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{badge}</td></tr>
            </table>"""
        else:
            result_html = '<p class="result error">User not found.</p>'
    except Exception as e:
        # Error exposed to user — reveals DB internals
        result_html = f'<p class="result error">Database error: {e}</p>'
    finally:
        conn.close()

    content = f"""
    <h1>User Profile</h1>
    <div class="card">
      <form action="/user" method="get">
        <input name="id" value="{user_id}" placeholder="User ID" style="width:120px;margin-right:8px;">
        <button type="submit">Lookup</button>
      </form>
      <div style="margin-top:16px;">{result_html}</div>
    </div>
    """
    return BASE.format(title="User Profile", content=content)


# ── 3. SQL Injection (login — time-blind possible) ────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # VULNERABLE: direct string interpolation
        try:
            c.execute(
                f"SELECT id, username, role FROM users "
                f"WHERE username = '{username}' AND password = '{password}'"
            )
            row = c.fetchone()
            if row:
                message = f'<div class="result">✅ Logged in as <b>{row[1]}</b> ({row[2]})</div>'
            else:
                message = '<div class="result error">Invalid credentials.</div>'
        except Exception as e:
            message = f'<div class="result error">Error: {e}</div>'
        finally:
            conn.close()

    content = f"""
    <h1>Login</h1>
    <div class="card" style="max-width:400px;">
      <form method="POST">
        <div style="margin-bottom:12px;">
          <label style="display:block;font-size:13px;margin-bottom:4px;">Username</label>
          <input name="username" style="width:100%;" placeholder="admin">
        </div>
        <div style="margin-bottom:16px;">
          <label style="display:block;font-size:13px;margin-bottom:4px;">Password</label>
          <input type="password" name="password" style="width:100%;" placeholder="••••••••">
        </div>
        <button type="submit" style="width:100%;">Sign in</button>
      </form>
      {message}
    </div>
    <p style="margin-top:12px;font-size:13px;color:#777;">
      Hint: try <code>admin' --</code> as username to bypass password.
    </p>
    """
    return BASE.format(title="Login", content=content)


# ── 4. Products ───────────────────────────────────────────────────────────────

@app.route("/products")
def products():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, price, description FROM products")
    rows = c.fetchall()
    conn.close()

    rows_html = "".join(
        f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>${r[2]:.2f}</td><td>{r[3]}</td>"
        f"<td><a href='/user?id={r[0]}'>view</a></td></tr>"
        for r in rows
    )
    content = f"""
    <h1>Products</h1>
    <div class="card">
      <table>
        <tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th><th></th></tr>
        {rows_html}
      </table>
    </div>
    """
    return BASE.format(title="Products", content=content)


# ── 5. Open Redirect ──────────────────────────────────────────────────────────

@app.route("/redirect")
def open_redirect():
    next_url = request.args.get("next", "/")
    # VULNERABLE: no validation of next_url — open redirect
    return redirect(next_url)


# ── 6. Path Traversal ─────────────────────────────────────────────────────────

@app.route("/file")
def path_traversal():
    filename = request.args.get("name", "readme.txt")
    # VULNERABLE: no path sanitisation
    try:
        base_dir = os.path.join(os.path.dirname(__file__), "static_files")
        os.makedirs(base_dir, exist_ok=True)
        # Write a sample file for benign requests
        with open(os.path.join(base_dir, "readme.txt"), "w") as f:
            f.write("VulnShop readme — nothing sensitive here.\n")
        full_path = os.path.join(base_dir, filename)
        with open(full_path, "r", errors="replace") as fh:
            content_text = fh.read()[:2000]
    except FileNotFoundError:
        content_text = "File not found."
    except PermissionError:
        content_text = "Permission denied."
    except Exception as e:
        content_text = f"Error: {e}"

    content = f"""
    <h1>File Viewer</h1>
    <div class="card">
      <form action="/file" method="get">
        <input name="name" value="{filename}" style="width:300px;margin-right:8px;">
        <button type="submit">Read</button>
      </form>
      <pre style="margin-top:16px;background:#f7fafc;padding:12px;border-radius:6px;font-size:13px;overflow:auto;">{content_text}</pre>
    </div>
    """
    return BASE.format(title="File Viewer", content=content)


# ── 7. Sensitive data exposure ────────────────────────────────────────────────

@app.route("/api/config")
def api_config():
    # VULNERABLE: exposes secrets in API response
    config = {
        "app_name": "VulnShop",
        "version": "1.0.0",
        "database_url": "sqlite:///tmp/vuln_target.db",
        "secret_key": "super_secret_key_do_not_share_abc123xyz",
        "api_keys": {
            "stripe": "sk_live_51FAKE_STRIPE_KEY_1234567890abcdef",
            "sendgrid": "SG.FAKE_SENDGRID_API_KEY.abcdefghijklmnopqrstuvwxyz",
            "aws_access": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        "admin_password": "admin123",
        "jwt_secret": "jwt_secret_1234",
        "debug": True,
        "allowed_hosts": ["*"],
    }
    response = jsonify(config)
    # No security headers added deliberately
    return response


# ── 8. SSRF ───────────────────────────────────────────────────────────────────

@app.route("/fetch")
def ssrf():
    url = request.args.get("url", "")
    result = ""
    if url:
        try:
            # VULNERABLE: fetches arbitrary URLs — SSRF
            req = urllib.request.Request(url, headers={"User-Agent": "VulnShop/1.0"})
            with urllib.request.urlopen(req, timeout=5) as response:
                result = response.read(2000).decode("utf-8", errors="replace")
        except Exception as e:
            result = f"Error fetching URL: {e}"

    content = f"""
    <h1>URL Fetcher</h1>
    <div class="card">
      <form action="/fetch" method="get">
        <input name="url" value="{url}" placeholder="https://example.com" style="width:400px;margin-right:8px;">
        <button type="submit">Fetch</button>
      </form>
      {"<pre style='margin-top:16px;background:#f7fafc;padding:12px;border-radius:6px;font-size:12px;overflow:auto;max-height:300px;'>" + result + "</pre>" if result else ""}
    </div>
    """
    return BASE.format(title="URL Fetcher", content=content)


# ── 9. SSTI (Jinja2) ─────────────────────────────────────────────────────────

@app.route("/greet")
def ssti():
    name = request.args.get("name", "World")
    # VULNERABLE: user input rendered directly through Jinja2 template engine
    template = f"<h1>Hello, {name}!</h1><p>Welcome to VulnShop.</p>"
    try:
        rendered = render_template_string(f"""
        {{% extends "base" %}}
        {template}
        """)
    except Exception:
        # Fallback: still vulnerable via direct render_template_string
        pass

    content = f"""
    <h1>Greeting</h1>
    <div class="card">
      <form action="/greet" method="get">
        <input name="name" value="{name}" placeholder="Your name" style="width:300px;margin-right:8px;">
        <button type="submit">Greet me</button>
      </form>
      <div class="result" style="margin-top:16px;">
        {render_template_string(f"Hello, {name}!")}
      </div>
    </div>
    <p style="margin-top:12px;font-size:13px;color:#777;">
      Hint: try <code>{{{{7*7}}}}</code> or <code>{{{{config}}}}</code> as name.
    </p>
    """
    return BASE.format(title="Greet", content=content)


# ── Response hook: intentionally missing security headers ─────────────────────

@app.after_request
def add_missing_headers(response):
    # VULNERABLE: deliberately NOT setting security headers
    # Real apps should set:
    #   Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
    #   Strict-Transport-Security, Referrer-Policy, Permissions-Policy
    response.headers.pop("X-Frame-Options", None)
    response.headers.pop("Content-Security-Policy", None)
    response.headers.pop("X-Content-Type-Options", None)
    response.headers.pop("Strict-Transport-Security", None)
    return response


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 54)
    print("  VulnShop - Deliberately Vulnerable Test Target")
    print("=" * 54)
    print("  URL:   http://localhost:5500")
    print("  Scan:  http://localhost:5500  (use in ProbeX)")
    print("")
    print("  Vulnerabilities embedded:")
    print("  [+] Reflected XSS       -> /search?q=")
    print("  [+] SQL Injection        -> /user?id=  and  /login")
    print("  [+] Open Redirect        -> /redirect?next=")
    print("  [+] Path Traversal       -> /file?name=")
    print("  [+] Sensitive Exposure   -> /api/config")
    print("  [+] SSRF                 -> /fetch?url=")
    print("  [+] SSTI                 -> /greet?name=")
    print("  [+] Missing Sec-Headers  -> all routes")
    print("=" * 54)
    print("  [!] DO NOT expose this on a public network!")
    print("=" * 54 + "\n")
    app.run(host="0.0.0.0", port=5500, debug=False)
