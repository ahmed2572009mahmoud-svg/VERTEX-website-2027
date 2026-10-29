# -*- coding: utf-8 -*-
"""
SMM Panel - موقع بيع خدمات السوشيال ميديا (Flask + SQLite)

تشغيل محلي:   python app.py
تشغيل إنتاج:  gunicorn -w 2 -b 0.0.0.0:8000 app:app
"""
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "panel.db"))


def _secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(BASE, ".secret_key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 14,
    MAX_CONTENT_LENGTH=256 * 1024,
)

try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo(os.environ.get("TZ_NAME", "Africa/Cairo"))
except Exception:  # لو مفيش tzdata على السيرفر
    LOCAL_TZ = timezone(timedelta(hours=2))

# ----------------------------------------------------------------------------
# قاعدة البيانات
# ----------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  balance REAL NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS services(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  rate REAL NOT NULL,
  min_qty INTEGER NOT NULL DEFAULT 10,
  max_qty INTEGER NOT NULL DEFAULT 10000,
  provider_service_id TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  service_id INTEGER,
  service_name TEXT NOT NULL,
  link TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  charge REAL NOT NULL,
  refunded REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  provider_order_id TEXT,
  start_count INTEGER,
  remains INTEGER,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE TABLE IF NOT EXISTS deposits(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  method TEXT NOT NULL,
  reference TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "site_name": "سوشيال بوست",
    "currency": "ج.م",
    "tagline": "زوّد متابعينك وتفاعلك بسرعة وبأسعار تنافسية",
    "payment_instructions": (
        "فودافون كاش: 01096078186\n"
        "حوّل المبلغ ثم أرسل رقم العملية في النموذج بالأسفل."
    ),
    "min_deposit": "20",
    "support_contact": "",
    "provider_url": "",
    "provider_key": "",
    "provider_fx": "1",
    "provider_markup": "30",
}

SAMPLE_SERVICES = [
    ("إنستجرام", "متابعين إنستجرام - جودة عالية", "يبدأ خلال دقائق. لا نطلب كلمة المرور أبداً.", 45.0, 100, 10000),
    ("إنستجرام", "لايكات إنستجرام", "لايكات على المنشور. الحساب لازم يكون عام.", 12.0, 50, 20000),
    ("تيك توك", "متابعين تيك توك", "الحساب لازم يكون عام أثناء التنفيذ.", 60.0, 100, 10000),
    ("تيك توك", "مشاهدات تيك توك", "مشاهدات للفيديو.", 5.0, 500, 100000),
    ("يوتيوب", "مشاهدات يوتيوب", "مشاهدات للفيديو.", 40.0, 500, 50000),
    ("فيسبوك", "لايكات صفحة فيسبوك", "لايكات ومتابعين للصفحة.", 55.0, 100, 10000),
]

STATUS_AR = {
    "pending": "قيد الانتظار",
    "processing": "جاري التجهيز",
    "in_progress": "قيد التنفيذ",
    "completed": "مكتمل",
    "partial": "مكتمل جزئياً",
    "canceled": "ملغي",
    "failed": "فشل",
}
ACTIVE_STATUSES = ("pending", "processing", "in_progress")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def connect():
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def tx(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


def init_db():
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        if conn.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 0:
            for i, (cat, name, desc, rate, mn, mx) in enumerate(SAMPLE_SERVICES):
                conn.execute(
                    "INSERT INTO services(category,name,description,rate,min_qty,max_qty,sort) "
                    "VALUES(?,?,?,?,?,?,?)", (cat, name, desc, rate, mn, mx, i))
        # إنشاء أدمن أول مرة
        conn.execute("BEGIN IMMEDIATE")
        has_admin = conn.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone()
        if not has_admin:
            username = os.environ.get("ADMIN_USERNAME", "admin")
            password = os.environ.get("ADMIN_PASSWORD")
            generated = False
            if not password:
                password = secrets.token_urlsafe(10)
                generated = True
            conn.execute(
                "INSERT INTO users(username,email,password_hash,is_admin,created_at) VALUES(?,?,?,?,?)",
                (username, os.environ.get("ADMIN_EMAIL", "admin@example.com"),
                 generate_password_hash(password), 1, now()))
            conn.execute("COMMIT")
            print("=" * 60)
            print(f"تم إنشاء حساب الأدمن:  {username}")
            if generated:
                print(f"كلمة المرور (احفظها دلوقتي، مش هتظهر تاني): {password}")
            print("=" * 60, flush=True)
        else:
            conn.execute("COMMIT")
    finally:
        conn.close()


def get_setting(key, default=""):
    row = get_db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row is not None:
        return row["value"]
    return DEFAULT_SETTINGS.get(key, default)


def set_setting(key, value):
    get_db().execute(
        "INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def all_settings():
    rows = get_db().execute("SELECT key,value FROM settings").fetchall()
    d = dict(DEFAULT_SETTINGS)
    d.update({r["key"]: r["value"] for r in rows})
    return d


# ----------------------------------------------------------------------------
# أدوات عامة: مستخدم، CSRF، فلاتر القوالب
# ----------------------------------------------------------------------------
def current_user():
    if "user" not in g:
        g.user = None
        uid = session.get("uid")
        if uid:
            g.user = get_db().execute(
                "SELECT * FROM users WHERE id=? AND is_active=1", (uid,)).fetchone()
            if g.user is None:
                session.clear()
    return g.user


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            flash("سجّل دخولك الأول.", "warn")
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return redirect(url_for("login", next=request.path))
        if not u["is_admin"]:
            abort(403)
        return fn(*a, **kw)
    return wrapper


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "").encode()
        good = session.get("csrf", "").encode()
        if not good or not hmac.compare_digest(sent, good):
            abort(400)


@app.context_processor
def inject_globals():
    s = all_settings()
    return {
        "S": s,
        "site_name": s["site_name"],
        "currency": s["currency"],
        "me": current_user(),
        "csrf_token": csrf_token,
        "STATUS_AR": STATUS_AR,
    }


@app.template_filter("money")
def money_filter(v):
    try:
        return f"{float(v):,.2f}"
    except (TypeError, ValueError):
        return "0.00"


@app.template_filter("dt")
def dt_filter(v):
    if not v:
        return "-"
    try:
        d = datetime.strptime(v, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return d.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return v


@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400,
                           msg="الطلب غير صالح أو انتهت الجلسة. حدّث الصفحة وجرّب تاني."), 400


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, msg="مش مسموح لك تدخل الصفحة دي."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="الصفحة غير موجودة."), 404


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", code=413, msg="الطلب كبير جداً."), 413


# تحديد محاولات الدخول (في الذاكرة)
_attempts = {}


def too_many_attempts(ip, limit=10, window=600):
    t = time.time()
    lst = [x for x in _attempts.get(ip, []) if t - x < window]
    _attempts[ip] = lst
    return len(lst) >= limit


def note_attempt(ip):
    _attempts.setdefault(ip, []).append(time.time())


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()


# ----------------------------------------------------------------------------
# المزوّد (Provider) - واجهة SMM API v2 القياسية
# ----------------------------------------------------------------------------
class ProviderError(Exception):
    pass


def provider_configured():
    return bool(get_setting("provider_url") and get_setting("provider_key"))


def provider_call(params):
    url = get_setting("provider_url").strip()
    key = get_setting("provider_key").strip()
    if not url or not key:
        raise ProviderError("المزوّد غير مضبوط. ضيف الرابط والمفتاح من الإعدادات.")
    if not re.match(r"^https?://", url):
        raise ProviderError("رابط المزوّد لازم يبدأ بـ http:// أو https://")
    data = urllib.parse.urlencode({"key": key, **params}).encode()
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "Mozilla/5.0 (SMMPanel)"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read(5 * 1024 * 1024).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        raise ProviderError(f"تعذّر الاتصال بالمزوّد: {e}")
    try:
        js = json.loads(body)
    except ValueError:
        raise ProviderError("رد غير مفهوم من المزوّد.")
    if isinstance(js, dict) and js.get("error"):
        raise ProviderError(str(js["error"]))
    return js


PROVIDER_STATUS_MAP = {
    "pending": "pending",
    "processing": "processing",
    "in progress": "in_progress",
    "inprogress": "in_progress",
    "completed": "completed",
    "partial": "partial",
    "canceled": "canceled",
    "cancelled": "canceled",
    "refunded": "canceled",
    "fail": "failed",
    "failed": "failed",
}


def to_int(v, default=None):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def refund_in_tx(db, order_id, amount):
    """استرجاع جزء من تكلفة الطلب لرصيد العميل (لازم يتنفذ جوا tx)."""
    o = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not o:
        return 0.0
    amount = round(min(float(amount), float(o["charge"]) - float(o["refunded"])), 2)
    if amount <= 0:
        return 0.0
    db.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, o["user_id"]))
    db.execute("UPDATE orders SET refunded=refunded+?, updated_at=? WHERE id=?",
               (amount, now(), order_id))
    return amount


def apply_status(db, order_id, status, remains=None, start_count=None, error=None):
    with tx(db):
        o = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not o:
            return
        db.execute(
            "UPDATE orders SET status=?, remains=COALESCE(?,remains), "
            "start_count=COALESCE(?,start_count), error=COALESCE(?,error), updated_at=? WHERE id=?",
            (status, remains, start_count, error, now(), order_id))
        if status in ("canceled", "failed"):
            refund_in_tx(db, order_id, o["charge"])
        elif status == "partial" and remains is not None and o["quantity"] > 0:
            part = min(max(remains, 0), o["quantity"]) / o["quantity"]
            refund_in_tx(db, order_id, float(o["charge"]) * part)


def submit_to_provider(db, order_id):
    """يبعت الطلب للمزوّد. يرجّع (ok, رسالة)."""
    o = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    svc = db.execute("SELECT * FROM services WHERE id=?", (o["service_id"],)).fetchone()
    if not svc or not svc["provider_service_id"] or not provider_configured():
        return False, "manual"
    try:
        js = provider_call({"action": "add", "service": svc["provider_service_id"],
                            "link": o["link"], "quantity": o["quantity"]})
        pid = js.get("order") if isinstance(js, dict) else None
        if not pid:
            raise ProviderError("المزوّد لم يرجّع رقم الطلب.")
    except ProviderError as e:
        apply_status(db, order_id, "failed", error=str(e)[:300])
        return False, str(e)
    db.execute("UPDATE orders SET provider_order_id=?, status='processing', updated_at=? WHERE id=?",
               (str(pid), now(), order_id))
    return True, str(pid)


def sync_order(db, o):
    if not o["provider_order_id"]:
        return False
    js = provider_call({"action": "status", "order": o["provider_order_id"]})
    if not isinstance(js, dict):
        return False
    status = PROVIDER_STATUS_MAP.get(str(js.get("status", "")).strip().lower())
    if not status:
        return False
    apply_status(db, o["id"], status, remains=to_int(js.get("remains")),
                 start_count=to_int(js.get("start_count")))
    return True


def sync_orders(db, rows):
    done = errors = 0
    for o in rows:
        try:
            if sync_order(db, o):
                done += 1
        except ProviderError:
            errors += 1
    return done, errors


# ----------------------------------------------------------------------------
# صفحات عامة + مستخدمين
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    services = db.execute(
        "SELECT * FROM services WHERE is_active=1 ORDER BY sort, id LIMIT 6").fetchall()
    stats = {
        "orders": db.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
        "users": db.execute("SELECT COUNT(*) FROM users WHERE is_admin=0").fetchone()[0],
    }
    return render_template("index.html", services=services, stats=stats)


@app.route("/services")
def services_page():
    rows = get_db().execute(
        "SELECT * FROM services WHERE is_active=1 ORDER BY category, sort, id").fetchall()
    grouped = {}
    for r in rows:
        grouped.setdefault(r["category"], []).append(r)
    return render_template("services.html", grouped=grouped)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("new_order"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        err = None
        if not re.match(r"^[A-Za-z0-9_]{3,20}$", username):
            err = "اسم المستخدم 3-20 حرف إنجليزي أو أرقام أو _ فقط."
        elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) or len(email) > 120:
            err = "البريد الإلكتروني غير صحيح."
        elif len(password) < 8:
            err = "كلمة المرور لازم تكون 8 أحرف على الأقل."
        elif password != password2:
            err = "كلمتا المرور غير متطابقتين."
        if not err:
            try:
                cur = get_db().execute(
                    "INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                    (username, email, generate_password_hash(password), now()))
                session.clear()
                session["uid"] = cur.lastrowid
                session.permanent = True
                flash("أهلاً بيك! حسابك اتعمل.", "ok")
                return redirect(url_for("add_funds"))
            except sqlite3.IntegrityError:
                err = "اسم المستخدم أو البريد مستخدم قبل كده."
        flash(err, "err")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("new_order"))
    if request.method == "POST":
        ip = client_ip()
        if too_many_attempts(ip):
            flash("محاولات كتير. استنى شوية وجرّب تاني.", "err")
            return render_template("login.html"), 429
        ident = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        u = get_db().execute(
            "SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1",
            (ident, ident.lower())).fetchone()
        if u and check_password_hash(u["password_hash"], password):
            session.clear()
            session["uid"] = u["id"]
            session.permanent = True
            nxt = request.args.get("next", "")
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = url_for("new_order")
            return redirect(nxt)
        note_attempt(ip)
        flash("بيانات الدخول غير صحيحة.", "err")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        u = current_user()
        old = request.form.get("old", "")
        new = request.form.get("new", "")
        if not check_password_hash(u["password_hash"], old):
            flash("كلمة المرور الحالية غلط.", "err")
        elif len(new) < 8:
            flash("كلمة المرور الجديدة لازم تكون 8 أحرف على الأقل.", "err")
        else:
            get_db().execute("UPDATE users SET password_hash=? WHERE id=?",
                             (generate_password_hash(new), u["id"]))
            flash("اتغيّرت كلمة المرور.", "ok")
            return redirect(url_for("account"))
    return render_template("account.html")


# ----------------------------------------------------------------------------
# الطلبات
# ----------------------------------------------------------------------------
@app.route("/new-order", methods=["GET", "POST"])
@login_required
def new_order():
    db = get_db()
    rows = db.execute("SELECT * FROM services WHERE is_active=1 ORDER BY category, sort, id").fetchall()
    services = [dict(r) for r in rows]
    if request.method == "POST":
        u = current_user()
        sid = to_int(request.form.get("service"))
        qty = to_int(request.form.get("quantity"))
        link = request.form.get("link", "").strip()
        svc = db.execute("SELECT * FROM services WHERE id=? AND is_active=1", (sid,)).fetchone()
        err = None
        if not svc:
            err = "اختار خدمة."
        elif not (3 <= len(link) <= 300):
            err = "اكتب الرابط أو اسم الحساب بشكل صحيح."
        elif qty is None or qty < svc["min_qty"] or qty > svc["max_qty"]:
            err = f"الكمية لازم تكون بين {svc['min_qty']} و {svc['max_qty']}."
        if err:
            flash(err, "err")
            return render_template("new_order.html", services=services, form=request.form)
        charge = round(float(svc["rate"]) * qty / 1000.0, 2)
        charge = max(charge, 0.01)
        with tx(db):
            bal = db.execute("SELECT balance FROM users WHERE id=?", (u["id"],)).fetchone()["balance"]
            if bal + 1e-9 < charge:
                ok = False
            else:
                ok = True
                db.execute("UPDATE users SET balance=balance-? WHERE id=?", (charge, u["id"]))
                cur = db.execute(
                    "INSERT INTO orders(user_id,service_id,service_name,link,quantity,charge,status,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (u["id"], svc["id"], svc["name"], link, qty, charge, "pending", now(), now()))
                oid = cur.lastrowid
        if not ok:
            flash(f"رصيدك مش كفاية. التكلفة {charge:.2f} {get_setting('currency')}.", "err")
            return redirect(url_for("add_funds"))
        submit_to_provider(db, oid)
        o = db.execute("SELECT status,error FROM orders WHERE id=?", (oid,)).fetchone()
        if o["status"] == "failed":
            flash("تعذّر تنفيذ الطلب حالياً واتسترجعت فلوسك لرصيدك. جرّب بعد شوية.", "err")
        else:
            flash(f"تم تسجيل طلبك رقم #{oid}.", "ok")
        return redirect(url_for("orders"))
    return render_template("new_order.html", services=services, form={})


@app.route("/orders")
@login_required
def orders():
    rows = get_db().execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 200",
        (current_user()["id"],)).fetchall()
    return render_template("orders.html", orders=rows)


@app.route("/orders/refresh", methods=["POST"])
@login_required
def orders_refresh():
    last = session.get("last_refresh", 0)
    if time.time() - last < 20:
        flash("استنى شوية قبل التحديث مرة تانية.", "warn")
        return redirect(url_for("orders"))
    session["last_refresh"] = time.time()
    db = get_db()
    rows = db.execute(
        "SELECT * FROM orders WHERE user_id=? AND status IN ('pending','processing','in_progress') "
        "AND provider_order_id IS NOT NULL ORDER BY id DESC LIMIT 20",
        (current_user()["id"],)).fetchall()
    if not rows:
        flash("مفيش طلبات نشطة تتحدّث.", "warn")
    else:
        done, errors = sync_orders(db, rows)
        flash(f"تم تحديث {done} طلب." + (" (حصلت مشكلة مع بعضها)" if errors else ""),
              "ok" if not errors else "warn")
    return redirect(url_for("orders"))


# ----------------------------------------------------------------------------
# الرصيد والإيداع
# ----------------------------------------------------------------------------
@app.route("/add-funds", methods=["GET", "POST"])
@login_required
def add_funds():
    db = get_db()
    u = current_user()
    if request.method == "POST":
        try:
            amount = round(float(request.form.get("amount", "0")), 2)
        except ValueError:
            amount = 0
        method = request.form.get("method", "").strip()[:40]
        ref = request.form.get("reference", "").strip()[:80]
        min_dep = float(get_setting("min_deposit", "20") or 0)
        err = None
        if amount < max(min_dep, 1):
            err = f"أقل مبلغ للشحن {max(min_dep, 1):g} {get_setting('currency')}."
        elif amount > 1_000_000:
            err = "المبلغ كبير جداً."
        elif not method:
            err = "اختار طريقة الدفع."
        elif len(ref) < 4:
            err = "اكتب رقم العملية أو رقم المحفظة اللي حوّلت منها."
        # A customer may submit multiple top-up requests from the same wallet/phone number.
        # Deposits are reviewed manually by the admin, so do not treat the sender phone as a unique transaction ID.
        if err:
            flash(err, "err")
        else:
            pending = db.execute(
                "SELECT COUNT(*) FROM deposits WHERE user_id=? AND status='pending'", (u["id"],)).fetchone()[0]
            if pending >= 5:
                flash("عندك طلبات شحن كتير قيد المراجعة. استنى لحد ما تتراجع.", "warn")
            else:
                db.execute(
                    "INSERT INTO deposits(user_id,amount,method,reference,created_at) VALUES(?,?,?,?,?)",
                    (u["id"], amount, method, ref, now()))
                flash("استلمنا طلب الشحن وهيتراجع قريب، وبعدها الرصيد بيتضاف تلقائي.", "ok")
                return redirect(url_for("add_funds"))
    deposits = db.execute(
        "SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC LIMIT 30", (u["id"],)).fetchall()
    return render_template("add_funds.html", deposits=deposits)


# ----------------------------------------------------------------------------
# لوحة الأدمن
# ----------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    q = lambda sql: db.execute(sql).fetchone()[0]  # noqa: E731
    stats = {
        "users": q("SELECT COUNT(*) FROM users WHERE is_admin=0"),
        "orders": q("SELECT COUNT(*) FROM orders"),
        "active_orders": q("SELECT COUNT(*) FROM orders WHERE status IN ('pending','processing','in_progress')"),
        "manual_orders": q("SELECT COUNT(*) FROM orders WHERE status='pending' AND provider_order_id IS NULL"),
        "pending_deposits": q("SELECT COUNT(*) FROM deposits WHERE status='pending'"),
        "revenue": q("SELECT COALESCE(SUM(charge-refunded),0) FROM orders"),
        "deposited": q("SELECT COALESCE(SUM(amount),0) FROM deposits WHERE status='approved'"),
        "balances": q("SELECT COALESCE(SUM(balance),0) FROM users WHERE is_admin=0"),
    }
    return render_template("admin/dashboard.html", stats=stats,
                           provider_ok=provider_configured())


@app.route("/admin/users")
@admin_required
def admin_users():
    search = request.args.get("q", "").strip()
    sql = "SELECT * FROM users"
    args = []
    if search:
        sql += " WHERE username LIKE ? OR email LIKE ?"
        args = [f"%{search}%", f"%{search}%"]
    sql += " ORDER BY id DESC LIMIT 200"
    return render_template("admin/users.html", users=get_db().execute(sql, args).fetchall(), q=search)


@app.route("/admin/users/<int:uid>/balance", methods=["POST"])
@admin_required
def admin_user_balance(uid):
    try:
        amount = round(float(request.form.get("amount", "0")), 2)
    except ValueError:
        amount = 0
    if amount == 0 or abs(amount) > 1_000_000:
        flash("اكتب مبلغ صحيح (موجب للإضافة، سالب للخصم).", "err")
        return redirect(url_for("admin_users"))
    db = get_db()
    with tx(db):
        u = db.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()
        if not u:
            abort(404)
        if u["balance"] + amount < 0:
            flash("الخصم أكبر من رصيد العميل.", "err")
            return redirect(url_for("admin_users"))
        db.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, uid))
    flash("تم تعديل الرصيد.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def admin_user_toggle(uid):
    if uid == current_user()["id"]:
        flash("متقدرش توقف حسابك.", "err")
    else:
        get_db().execute("UPDATE users SET is_active=1-is_active WHERE id=?", (uid,))
        flash("تم التعديل.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/services")
@admin_required
def admin_services():
    rows = get_db().execute("SELECT * FROM services ORDER BY category, sort, id").fetchall()
    return render_template("admin/services.html", services=rows)


def _service_from_form():
    f = request.form
    try:
        rate = round(float(f.get("rate", "0")), 4)
    except ValueError:
        rate = 0
    mn, mx = to_int(f.get("min_qty"), 0), to_int(f.get("max_qty"), 0)
    data = {
        "category": f.get("category", "").strip()[:60],
        "name": f.get("name", "").strip()[:150],
        "description": f.get("description", "").strip()[:500],
        "rate": rate, "min_qty": mn, "max_qty": mx,
        "provider_service_id": f.get("provider_service_id", "").strip()[:40] or None,
        "sort": to_int(f.get("sort"), 0),
        "is_active": 1 if f.get("is_active") else 0,
    }
    err = None
    if not data["category"] or not data["name"]:
        err = "القسم والاسم مطلوبين."
    elif rate <= 0:
        err = "السعر لازم يكون أكبر من صفر."
    elif mn <= 0 or mx < mn:
        err = "الحد الأدنى/الأقصى غير صحيح."
    return data, err


@app.route("/admin/services/new", methods=["GET", "POST"])
@admin_required
def admin_service_new():
    if request.method == "POST":
        data, err = _service_from_form()
        if err:
            flash(err, "err")
            return render_template("admin/service_form.html", s=data, new=True)
        get_db().execute(
            "INSERT INTO services(category,name,description,rate,min_qty,max_qty,provider_service_id,sort,is_active) "
            "VALUES(:category,:name,:description,:rate,:min_qty,:max_qty,:provider_service_id,:sort,:is_active)", data)
        flash("اتضافت الخدمة.", "ok")
        return redirect(url_for("admin_services"))
    return render_template("admin/service_form.html", new=True,
                           s={"is_active": 1, "min_qty": 100, "max_qty": 10000, "sort": 0})


@app.route("/admin/services/<int:sid>/edit", methods=["GET", "POST"])
@admin_required
def admin_service_edit(sid):
    db = get_db()
    s = db.execute("SELECT * FROM services WHERE id=?", (sid,)).fetchone()
    if not s:
        abort(404)
    if request.method == "POST":
        data, err = _service_from_form()
        if err:
            flash(err, "err")
            data["id"] = sid
            return render_template("admin/service_form.html", s=data, new=False)
        data["id"] = sid
        db.execute(
            "UPDATE services SET category=:category,name=:name,description=:description,rate=:rate,"
            "min_qty=:min_qty,max_qty=:max_qty,provider_service_id=:provider_service_id,"
            "sort=:sort,is_active=:is_active WHERE id=:id", data)
        flash("اتحفظت التعديلات.", "ok")
        return redirect(url_for("admin_services"))
    return render_template("admin/service_form.html", s=s, new=False)


@app.route("/admin/services/<int:sid>/delete", methods=["POST"])
@admin_required
def admin_service_delete(sid):
    get_db().execute("DELETE FROM services WHERE id=?", (sid,))
    flash("اتحذفت الخدمة.", "ok")
    return redirect(url_for("admin_services"))


@app.route("/admin/services/bulk-delete", methods=["POST"])
@admin_required
def admin_services_bulk_delete():
    db = get_db()
    action = request.form.get("action", "selected")
    if action == "all":
        count = db.execute("SELECT COUNT(*) FROM services").fetchone()[0]
        db.execute("DELETE FROM services")
        flash(f"تم حذف كل الخدمات ({count}). الطلبات القديمة ستظل محفوظة.", "ok")
        return redirect(url_for("admin_services"))

    raw_ids = request.form.getlist("service_ids")
    ids = []
    for value in raw_ids:
        try:
            sid = int(value)
        except (TypeError, ValueError):
            continue
        if sid > 0 and sid not in ids:
            ids.append(sid)
    if not ids:
        flash("حدد خدمة واحدة على الأقل قبل الحذف.", "err")
        return redirect(url_for("admin_services"))

    placeholders = ",".join("?" for _ in ids)
    cur = db.execute(f"DELETE FROM services WHERE id IN ({placeholders})", ids)
    flash(f"تم حذف {cur.rowcount} خدمة. الطلبات القديمة ستظل محفوظة.", "ok")
    return redirect(url_for("admin_services"))


@app.route("/admin/services/import", methods=["GET", "POST"])
@admin_required
def admin_services_import():
    db = get_db()
    if request.method == "POST":
        try:
            fx = float(request.form.get("fx", "1") or 1)
            markup = float(request.form.get("markup", "0") or 0)
        except ValueError:
            flash("سعر الصرف أو نسبة الربح غير صحيحة.", "err")
            return redirect(url_for("admin_services_import"))
        if fx <= 0 or markup < -50:
            flash("قيم غير صحيحة.", "err")
            return redirect(url_for("admin_services_import"))
        keyword = request.form.get("keyword", "").strip().lower()
        try:
            data = provider_call({"action": "services"})
        except ProviderError as e:
            flash(str(e), "err")
            return redirect(url_for("admin_services_import"))
        if not isinstance(data, list):
            flash("شكل رد المزوّد غير متوقع.", "err")
            return redirect(url_for("admin_services_import"))
        set_setting("provider_fx", str(fx))
        set_setting("provider_markup", str(markup))
        added = updated = 0
        with tx(db):
            for item in data:
                try:
                    pid = str(item["service"])
                    name = str(item.get("name", ""))[:150]
                    cat = str(item.get("category", "عام"))[:60]
                    if keyword and keyword not in (name + " " + cat).lower():
                        continue
                    price = round(float(item["rate"]) * fx * (1 + markup / 100.0), 4)
                    mn, mx = to_int(item.get("min"), 1), to_int(item.get("max"), 100000)
                except (KeyError, ValueError, TypeError):
                    continue
                if price <= 0:
                    continue
                ex = db.execute("SELECT id FROM services WHERE provider_service_id=?", (pid,)).fetchone()
                if ex:
                    db.execute("UPDATE services SET rate=?, min_qty=?, max_qty=? WHERE id=?",
                               (price, mn, mx, ex["id"]))
                    updated += 1
                else:
                    db.execute(
                        "INSERT INTO services(category,name,description,rate,min_qty,max_qty,provider_service_id,is_active) "
                        "VALUES(?,?,?,?,?,?,?,1)", (cat, name, "", price, mn, mx, pid))
                    added += 1
        flash(f"تم الاستيراد: {added} خدمة جديدة، و{updated} اتحدّثت.", "ok")
        return redirect(url_for("admin_services"))
    return render_template("admin/import.html", provider_ok=provider_configured())


@app.route("/admin/orders")
@admin_required
def admin_orders():
    status = request.args.get("status", "")
    sql = ("SELECT o.*, u.username FROM orders o JOIN users u ON u.id=o.user_id")
    args = []
    if status in STATUS_AR:
        sql += " WHERE o.status=?"
        args.append(status)
    sql += " ORDER BY o.id DESC LIMIT 300"
    return render_template("admin/orders.html", orders=get_db().execute(sql, args).fetchall(),
                           status=status)


@app.route("/admin/orders/<int:oid>/status", methods=["POST"])
@admin_required
def admin_order_status(oid):
    status = request.form.get("status", "")
    if status not in STATUS_AR:
        abort(400)
    remains = to_int(request.form.get("remains"))
    apply_status(get_db(), oid, status, remains=remains)
    flash("تم تحديث حالة الطلب" + (" واسترجاع المبلغ للعميل." if status in ("canceled", "failed", "partial") else "."), "ok")
    return redirect(request.referrer or url_for("admin_orders"))


@app.route("/admin/orders/<int:oid>/send", methods=["POST"])
@admin_required
def admin_order_send(oid):
    db = get_db()
    o = db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not o or o["provider_order_id"] or o["status"] != "pending":
        flash("الطلب ده مينفعش يتبعت للمزوّد.", "err")
    else:
        ok, msg = submit_to_provider(db, oid)
        flash("اتبعت للمزوّد." if ok else f"ماتبعتش: {msg}", "ok" if ok else "err")
    return redirect(request.referrer or url_for("admin_orders"))


@app.route("/admin/orders/sync", methods=["POST"])
@admin_required
def admin_orders_sync():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM orders WHERE status IN ('pending','processing','in_progress') "
        "AND provider_order_id IS NOT NULL ORDER BY id LIMIT 100").fetchall()
    done, errors = sync_orders(db, rows)
    flash(f"تم تحديث {done} طلب" + (f" ({errors} فشل)" if errors else "") + ".", "ok" if not errors else "warn")
    return redirect(url_for("admin_orders"))


@app.route("/admin/deposits")
@admin_required
def admin_deposits():
    status = request.args.get("status", "pending")
    sql = ("SELECT d.*, u.username FROM deposits d JOIN users u ON u.id=d.user_id")
    args = []
    if status in ("pending", "approved", "rejected"):
        sql += " WHERE d.status=?"
        args.append(status)
    sql += " ORDER BY d.id DESC LIMIT 300"
    return render_template("admin/deposits.html", deposits=get_db().execute(sql, args).fetchall(),
                           status=status)


@app.route("/admin/deposits/<int:did>/<action>", methods=["POST"])
@admin_required
def admin_deposit_review(did, action):
    if action not in ("approve", "reject"):
        abort(404)
    db = get_db()
    with tx(db):
        d = db.execute("SELECT * FROM deposits WHERE id=? AND status='pending'", (did,)).fetchone()
        if d:
            if action == "approve":
                db.execute("UPDATE users SET balance=balance+? WHERE id=?", (d["amount"], d["user_id"]))
            db.execute("UPDATE deposits SET status=?, reviewed_at=? WHERE id=?",
                       ("approved" if action == "approve" else "rejected", now(), did))
    flash("تمت الموافقة وإضافة الرصيد." if d and action == "approve" else
          ("تم الرفض." if d else "الطلب اتراجع قبل كده."), "ok")
    return redirect(request.referrer or url_for("admin_deposits"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        f = request.form
        url = f.get("provider_url", "").strip()
        if url and not re.match(r"^https?://", url):
            flash("رابط المزوّد لازم يبدأ بـ http:// أو https://", "err")
            return redirect(url_for("admin_settings"))
        for key in ("site_name", "currency", "tagline", "payment_instructions",
                    "support_contact", "min_deposit"):
            set_setting(key, f.get(key, "").strip()[:1000])
        set_setting("provider_url", url)
        if f.get("provider_key", "").strip():
            set_setting("provider_key", f["provider_key"].strip())
        if f.get("clear_key"):
            set_setting("provider_key", "")
        flash("اتحفظت الإعدادات.", "ok")
        return redirect(url_for("admin_settings"))
    return render_template("admin/settings.html", has_key=bool(get_setting("provider_key")))


@app.route("/admin/provider-balance", methods=["POST"])
@admin_required
def admin_provider_balance():
    try:
        js = provider_call({"action": "balance"})
        flash(f"رصيدك عند المزوّد: {js.get('balance')} {js.get('currency', '')}", "ok")
    except ProviderError as e:
        flash(str(e), "err")
    return redirect(url_for("admin_dashboard"))


# ----------------------------------------------------------------------------
# أوامر سطر الأوامر
# ----------------------------------------------------------------------------
@app.cli.command("sync-orders")
def cli_sync_orders():
    """تحديث حالة الطلبات النشطة من المزوّد (حطه في cron كل 5 دقايق)."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM orders WHERE status IN ('pending','processing','in_progress') "
        "AND provider_order_id IS NOT NULL ORDER BY id LIMIT 500").fetchall()
    done, errors = sync_orders(db, rows)
    print(f"synced={done} errors={errors}")


@app.cli.command("set-password")
def cli_set_password():
    """flask --app app set-password USERNAME NEWPASSWORD"""
    import sys
    args = [a for a in sys.argv[1:] if not a.startswith("-")][-2:]
    if len(args) != 2:
        print("usage: flask --app app set-password USERNAME NEWPASSWORD")
        return
    db = get_db()
    db.execute("UPDATE users SET password_hash=? WHERE username=?",
               (generate_password_hash(args[1]), args[0]))
    print("done")


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("DEBUG") == "1")
