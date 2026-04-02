import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "inventory.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "replace-this-in-production"


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS kits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            serial_number TEXT UNIQUE NOT NULL,
            markers TEXT,
            kit_id INTEGER NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (kit_id) REFERENCES kits(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS loans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            borrower_user_id INTEGER NOT NULL,
            kit_id INTEGER NULL,
            signed_by_user_id INTEGER NOT NULL,
            signed_at TEXT NOT NULL,
            returned_at TEXT NULL,
            return_processed_by_user_id INTEGER NULL,
            notes TEXT,
            status TEXT NOT NULL CHECK(status IN ('active','closed')),
            FOREIGN KEY (borrower_user_id) REFERENCES users(id),
            FOREIGN KEY (kit_id) REFERENCES kits(id),
            FOREIGN KEY (signed_by_user_id) REFERENCES users(id),
            FOREIGN KEY (return_processed_by_user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS loan_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            loan_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            returned_present INTEGER NULL,
            return_note TEXT,
            FOREIGN KEY (loan_id) REFERENCES loans(id) ON DELETE CASCADE,
            FOREIGN KEY (item_id) REFERENCES items(id)
        );
        """
    )
    db.commit()
    db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = get_db().execute("SELECT is_admin FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or user["is_admin"] != 1:
            flash("הפעולה מותרת למנהל בלבד", "error")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


@app.context_processor
def inject_current_user():
    user = None
    if session.get("user_id"):
        user = get_db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return {"current_user": user}


@app.route("/")
@login_required
def index():
    db = get_db()
    kits = db.execute(
        """
        SELECT k.*, 
               EXISTS(SELECT 1 FROM loans l WHERE l.kit_id = k.id AND l.status='active') AS is_loaned
        FROM kits k
        ORDER BY k.name
        """
    ).fetchall()

    unassigned_items = db.execute(
        """
        SELECT i.*, 
               EXISTS(
                   SELECT 1 FROM loan_items li
                   JOIN loans l ON l.id = li.loan_id
                   WHERE li.item_id=i.id AND l.status='active'
               ) AS is_loaned
        FROM items i
        WHERE i.kit_id IS NULL
        ORDER BY i.name
        """
    ).fetchall()

    active_loans = db.execute(
        """
        SELECT l.id, l.signed_at, l.is_exception, u.full_name AS borrower_name, k.name AS kit_name
        SELECT l.id, l.signed_at, u.full_name AS borrower_name, k.name AS kit_name
        FROM loans l
        JOIN users u ON u.id = l.borrower_user_id
        LEFT JOIN kits k ON k.id = l.kit_id
        WHERE l.status='active'
        ORDER BY l.signed_at DESC
        """
    ).fetchall()

    return render_template("index.html", kits=kits, unassigned_items=unassigned_items, active_loans=active_loans)


@app.route("/register", methods=["GET", "POST"])
@login_required
@admin_required
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        full_name = request.form["full_name"].strip()
        password = request.form["password"]
        if not username or not full_name or not password:
            flash("יש למלא את כל השדות", "error")
            return render_template("register.html")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, full_name, password_hash, is_admin, created_at) VALUES (?,?,?,?,?)",
                (username, full_name, generate_password_hash(password), int(request.form.get("is_admin") == "on"), now_iso()),
                "INSERT INTO users (username, full_name, password_hash, created_at) VALUES (?,?,?,?)",
                (username, full_name, generate_password_hash(password), now_iso()),
            )
            db.commit()
            flash("המשתמש נוצר בהצלחה", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("שם המשתמש כבר קיים", "error")

    return render_template("register.html")


@app.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    db = get_db()
    has_users = db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
    if has_users:
        flash("כבר קיים משתמש במערכת. יצירת משתמשים נוספים דרך מנהל בלבד", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"].strip()
        full_name = request.form["full_name"].strip()
        password = request.form["password"]
        if not username or not full_name or not password:
            flash("יש למלא את כל השדות", "error")
            return render_template("setup_admin.html")

        db.execute(
            "INSERT INTO users (username, full_name, password_hash, is_admin, created_at) VALUES (?,?,?,?,?)",
            (username, full_name, generate_password_hash(password), 1, now_iso()),
        )
        db.commit()
        flash("מנהל ראשי נוצר בהצלחה. ניתן להתחבר", "success")
        return redirect(url_for("login"))

    return render_template("setup_admin.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        flash("פרטי התחברות שגויים", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/kits/new", methods=["GET", "POST"])
@login_required
@admin_required
def new_kit():
    if request.method == "POST":
        name = request.form["name"].strip()
        notes = request.form.get("notes", "").strip()
        if not name:
            flash("שם סט הוא שדה חובה", "error")
            return render_template("new_kit.html")
        db = get_db()
        try:
            db.execute("INSERT INTO kits (name, notes, created_at) VALUES (?,?,?)", (name, notes, now_iso()))
            db.commit()
            flash("הסט נוצר", "success")
            return redirect(url_for("index"))
        except sqlite3.IntegrityError:
            flash("שם סט כבר קיים", "error")

    return render_template("new_kit.html")


@app.route("/items/new", methods=["GET", "POST"])
@login_required
def new_item():
    db = get_db()
    kits = db.execute("SELECT * FROM kits ORDER BY name").fetchall()
    if request.method == "POST":
        name = request.form["name"].strip()
        serial = request.form["serial_number"].strip()
        markers = request.form.get("markers", "").strip()
        kit_id_raw = request.form.get("kit_id")
        kit_id = int(kit_id_raw) if kit_id_raw else None
        if not name or not serial:
            flash("שם פריט ומספר סיריאלי הם שדות חובה", "error")
            return render_template("new_item.html", kits=kits)
        try:
            db.execute(
                "INSERT INTO items (name, serial_number, markers, kit_id, created_at) VALUES (?,?,?,?,?)",
                (name, serial, markers, kit_id, now_iso()),
            )
            db.commit()
            flash("פריט נוסף", "success")
            return redirect(url_for("index"))
        except sqlite3.IntegrityError:
            flash("מספר סיריאלי כבר קיים", "error")

    return render_template("new_item.html", kits=kits)


@app.route("/loans/new", methods=["GET", "POST"])
@login_required
def new_loan():
    db = get_db()
    users = db.execute("SELECT id, full_name FROM users ORDER BY full_name").fetchall()
    kits = db.execute(
        """
        SELECT k.* FROM kits k
        WHERE NOT EXISTS (SELECT 1 FROM loans l WHERE l.kit_id=k.id AND l.status='active')
        ORDER BY k.name
        """
    ).fetchall()
    kit_items_map = {
        kit["id"]: db.execute("SELECT id, name, serial_number FROM items WHERE kit_id=? ORDER BY name", (kit["id"],)).fetchall()
        for kit in kits
    }
    standalone_items = db.execute(
        """
        SELECT i.* FROM items i
        WHERE i.kit_id IS NULL AND NOT EXISTS (
            SELECT 1 FROM loan_items li JOIN loans l ON l.id=li.loan_id
            WHERE li.item_id=i.id AND l.status='active'
        )
        ORDER BY i.name
        """
    ).fetchall()

    if request.method == "POST":
        borrower_user_id = int(request.form["borrower_user_id"])
        kit_id = request.form.get("kit_id")
        kit_id = int(kit_id) if kit_id else None
        extra_item_ids = [int(x) for x in request.form.getlist("extra_item_ids")]
        notes = request.form.get("notes", "").strip()
        exception_note = None

        selected_kit_item_ids = []
        all_kit_item_ids = []
        if kit_id:
            all_kit_item_ids = [row["id"] for row in kit_items_map.get(kit_id, [])]
            selected_kit_item_ids = [int(x) for x in request.form.getlist(f"kit_item_ids_{kit_id}")]
            selected_kit_item_ids = [item_id for item_id in selected_kit_item_ids if item_id in all_kit_item_ids]

        if not selected_kit_item_ids and not extra_item_ids:
            flash("יש לבחור לפחות סט אחד או פריט אקסטרא אחד", "error")
            return render_template(
                "new_loan.html",
                users=users,
                kits=kits,
                standalone_items=standalone_items,
                kit_items_map=kit_items_map,
            )

        is_exception = 1 if kit_id and len(selected_kit_item_ids) < len(all_kit_item_ids) else 0
        if is_exception:
            exception_note = "חתימה חלקית על קיט: לא כל הפריטים נחתמו"

        cur = db.execute(
            """
            INSERT INTO loans (borrower_user_id, kit_id, signed_by_user_id, signed_at, notes, is_exception, exception_note, status)
            VALUES (?,?,?,?,?,?,?, 'active')
            """,
            (borrower_user_id, kit_id, session["user_id"], now_iso(), notes, is_exception, exception_note),

        if not kit_id and not extra_item_ids:
            flash("יש לבחור לפחות סט אחד או פריט אקסטרא אחד", "error")
            return render_template("new_loan.html", users=users, kits=kits, standalone_items=standalone_items)

        cur = db.execute(
            """
            INSERT INTO loans (borrower_user_id, kit_id, signed_by_user_id, signed_at, notes, status)
            VALUES (?,?,?,?,?, 'active')
            """,
            (borrower_user_id, kit_id, session["user_id"], now_iso(), notes),
        )
        loan_id = cur.lastrowid

        item_ids = set(extra_item_ids)
        item_ids.update(selected_kit_item_ids)
        if kit_id:
            kit_items = db.execute("SELECT id FROM items WHERE kit_id=?", (kit_id,)).fetchall()
            item_ids.update(row["id"] for row in kit_items)

        for item_id in item_ids:
            db.execute("INSERT INTO loan_items (loan_id, item_id) VALUES (?,?)", (loan_id, item_id))

        db.commit()
        flash("השאלה נרשמה", "success")
        return redirect(url_for("index"))

    return render_template(
        "new_loan.html",
        users=users,
        kits=kits,
        standalone_items=standalone_items,
        kit_items_map=kit_items_map,
    )
    return render_template("new_loan.html", users=users, kits=kits, standalone_items=standalone_items)


@app.route("/loans/<int:loan_id>/return", methods=["GET", "POST"])
@login_required
def return_loan(loan_id: int):
    db = get_db()
    loan = db.execute(
        """
        SELECT l.*, u.full_name AS borrower_name, k.name AS kit_name
        FROM loans l
        JOIN users u ON u.id = l.borrower_user_id
        LEFT JOIN kits k ON k.id = l.kit_id
        WHERE l.id=?
        """,
        (loan_id,),
    ).fetchone()

    if loan is None:
        flash("השאלה לא נמצאה", "error")
        return redirect(url_for("index"))

    if loan["status"] == "closed":
        flash("השאלה כבר נסגרה", "error")
        return redirect(url_for("index"))

    items = db.execute(
        """
        SELECT li.id AS loan_item_id, i.name, i.serial_number
        FROM loan_items li
        JOIN items i ON i.id = li.item_id
        WHERE li.loan_id=?
        ORDER BY i.name
        """,
        (loan_id,),
    ).fetchall()

    if request.method == "POST":
        for item in items:
            present = 1 if request.form.get(f"present_{item['loan_item_id']}") == "on" else 0
            note = request.form.get(f"note_{item['loan_item_id']}", "").strip()
            db.execute(
                "UPDATE loan_items SET returned_present=?, return_note=? WHERE id=?",
                (present, note, item["loan_item_id"]),
            )

        db.execute(
            """
            UPDATE loans
            SET status='closed', returned_at=?, return_processed_by_user_id=?
            WHERE id=?
            """,
            (now_iso(), session["user_id"], loan_id),
        )
        db.commit()
        flash("תהליך זיכוי הושלם", "success")
        return redirect(url_for("index"))

    return render_template("return_loan.html", loan=loan, items=items)


@app.route("/my-signatures")
@login_required
def my_signatures():
    db = get_db()
    loans = db.execute(
        """
        SELECT l.id, l.signed_at, k.name AS kit_name
        FROM loans l
        LEFT JOIN kits k ON k.id = l.kit_id
        WHERE l.borrower_user_id=? AND l.status='active'
        ORDER BY l.signed_at DESC
        """,
        (session["user_id"],),
    ).fetchall()

    items = db.execute(
        """
        SELECT DISTINCT i.name, i.serial_number, k.name AS kit_name
        FROM loans l
        JOIN loan_items li ON li.loan_id=l.id
        JOIN items i ON i.id=li.item_id
        LEFT JOIN kits k ON k.id=i.kit_id
        WHERE l.borrower_user_id=? AND l.status='active'
        ORDER BY i.name
        """,
        (session["user_id"],),
    ).fetchall()

    return render_template("my_signatures.html", loans=loans, items=items)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
