import os
import sqlite3
import hashlib
import secrets
import hmac
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import date, timedelta

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "data", "library.db")
FINE_PER_DAY = 20  # Change this amount if required (currency units per day)


def hash_password(password, salt=None):
    """PBKDF2 password hash; store salt and digest, never plaintext."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, digest_hex):
    salt = bytes.fromhex(salt_hex)
    _, candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, digest_hex)


class LibraryDB:
    def __init__(self, path=DB_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.create_schema()
        self.seed_data()

    def create_schema(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            isbn TEXT UNIQUE,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'General',
            total_copies INTEGER NOT NULL CHECK(total_copies >= 0),
            available_copies INTEGER NOT NULL CHECK(available_copies >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK(available_copies <= total_copies)
        );
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_no TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS loans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id INTEGER NOT NULL REFERENCES books(id) ON DELETE RESTRICT,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE RESTRICT,
            issue_date TEXT NOT NULL,
            due_date TEXT NOT NULL,
            return_date TEXT,
            fine INTEGER NOT NULL DEFAULT 0 CHECK(fine >= 0)
        );
        CREATE INDEX IF NOT EXISTS idx_books_title ON books(title);
        CREATE INDEX IF NOT EXISTS idx_students_roll ON students(roll_no);
        CREATE INDEX IF NOT EXISTS idx_loans_return ON loans(return_date);
        """)
        self.conn.commit()

    def seed_data(self):
        row = self.conn.execute("SELECT id FROM admins LIMIT 1").fetchone()
        if not row:
            salt, digest = hash_password("Admin@123")
            self.conn.execute(
                "INSERT INTO admins(username, salt, password_hash) VALUES (?, ?, ?)",
                ("admin", salt, digest)
            )

        if self.conn.execute("SELECT COUNT(*) FROM books").fetchone()[0] == 0:
            self.conn.executemany("""
                INSERT INTO books(isbn, title, author, category, total_copies, available_copies)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [
                ("9780132350884", "Clean Code", "Robert C. Martin", "Programming", 5, 5),
                ("9780134685991", "Effective Java", "Joshua Bloch", "Programming", 3, 3),
                ("9780596009205", "Head First Design Patterns", "Eric Freeman", "Software Design", 4, 4),
                ("9781492056355", "Fluent Python", "Luciano Ramalho", "Python", 2, 2),
                ("9780262033848", "Introduction to Algorithms", "Cormen et al.", "Algorithms", 3, 3),
            ])

        if self.conn.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 0:
            self.conn.executemany("""
                INSERT INTO students(roll_no, name, email, phone) VALUES (?, ?, ?, ?)
            """, [
                ("BSCS-001", "Ali Ahmed", "ali@example.com", "03001234567"),
                ("BSCS-002", "Ayesha Khan", "ayesha@example.com", "03007654321"),
                ("BSCS-003", "Usman Raza", "usman@example.com", "03111234567"),
            ])
        self.conn.commit()

    def login(self, username, password):
        row = self.conn.execute(
            "SELECT salt, password_hash FROM admins WHERE username = ?", (username.strip(),)
        ).fetchone()
        return bool(row and verify_password(password, row["salt"], row["password_hash"]))

    def change_password(self, username, old_password, new_password):
        row = self.conn.execute(
            "SELECT id, salt, password_hash FROM admins WHERE username = ?", (username,)
        ).fetchone()
        if not row or not verify_password(old_password, row["salt"], row["password_hash"]):
            return False
        salt, digest = hash_password(new_password)
        self.conn.execute("UPDATE admins SET salt=?, password_hash=? WHERE id=?",
                          (salt, digest, row["id"]))
        self.conn.commit()
        return True

    def stats(self):
        return {
            "titles": self.conn.execute("SELECT COUNT(*) FROM books").fetchone()[0],
            "copies": self.conn.execute("SELECT COALESCE(SUM(total_copies),0) FROM books").fetchone()[0],
            "available": self.conn.execute("SELECT COALESCE(SUM(available_copies),0) FROM books").fetchone()[0],
            "students": self.conn.execute("SELECT COUNT(*) FROM students").fetchone()[0],
            "active": self.conn.execute("SELECT COUNT(*) FROM loans WHERE return_date IS NULL").fetchone()[0],
            "overdue": self.conn.execute(
                "SELECT COUNT(*) FROM loans WHERE return_date IS NULL AND due_date < ?", (date.today().isoformat(),)
            ).fetchone()[0],
        }

    def list_books(self, search=""):
        pattern = f"%{search.strip()}%"
        return self.conn.execute("""
            SELECT * FROM books
            WHERE title LIKE ? OR author LIKE ? OR COALESCE(isbn,'') LIKE ? OR category LIKE ?
            ORDER BY title
        """, (pattern, pattern, pattern, pattern)).fetchall()

    def add_book(self, isbn, title, author, category, copies):
        self.conn.execute("""
            INSERT INTO books(isbn,title,author,category,total_copies,available_copies)
            VALUES (?,?,?,?,?,?)
        """, (isbn or None, title.strip(), author.strip(), category.strip() or "General", copies, copies))
        self.conn.commit()

    def update_book(self, book_id, isbn, title, author, category, total):
        row = self.conn.execute("SELECT total_copies, available_copies FROM books WHERE id=?",
                                (book_id,)).fetchone()
        if not row:
            raise ValueError("Book record not found.")
        currently_loaned = row["total_copies"] - row["available_copies"]
        if total < currently_loaned:
            raise ValueError(f"Total copies cannot be less than {currently_loaned} currently loaned copy/copies.")
        available = total - currently_loaned
        self.conn.execute("""
            UPDATE books SET isbn=?, title=?, author=?, category=?, total_copies=?, available_copies=?
            WHERE id=?
        """, (isbn or None, title.strip(), author.strip(), category.strip() or "General",
              total, available, book_id))
        self.conn.commit()

    def delete_book(self, book_id):
        self.conn.execute("DELETE FROM books WHERE id=?", (book_id,))
        self.conn.commit()

    def list_students(self, search=""):
        pattern = f"%{search.strip()}%"
        return self.conn.execute("""
            SELECT * FROM students
            WHERE roll_no LIKE ? OR name LIKE ? OR COALESCE(email,'') LIKE ? OR COALESCE(phone,'') LIKE ?
            ORDER BY name
        """, (pattern, pattern, pattern, pattern)).fetchall()

    def add_student(self, roll, name, email, phone):
        self.conn.execute("INSERT INTO students(roll_no,name,email,phone) VALUES (?,?,?,?)",
                          (roll.strip(), name.strip(), email.strip(), phone.strip()))
        self.conn.commit()

    def update_student(self, student_id, roll, name, email, phone):
        self.conn.execute("""
            UPDATE students SET roll_no=?, name=?, email=?, phone=? WHERE id=?
        """, (roll.strip(), name.strip(), email.strip(), phone.strip(), student_id))
        self.conn.commit()

    def delete_student(self, student_id):
        self.conn.execute("DELETE FROM students WHERE id=?", (student_id,))
        self.conn.commit()

    def issue_book(self, book_id, student_id, days):
        book = self.conn.execute("SELECT available_copies FROM books WHERE id=?", (book_id,)).fetchone()
        if not book:
            raise ValueError("Please select a valid book.")
        if book["available_copies"] < 1:
            raise ValueError("No copies of this book are currently available.")
        student = self.conn.execute("SELECT id FROM students WHERE id=?", (student_id,)).fetchone()
        if not student:
            raise ValueError("Please select a valid student.")
        existing = self.conn.execute("""
            SELECT id FROM loans WHERE book_id=? AND student_id=? AND return_date IS NULL
        """, (book_id, student_id)).fetchone()
        if existing:
            raise ValueError("This student already has an active loan for this book.")
        issued = date.today()
        due = issued + timedelta(days=days)
        with self.conn:
            self.conn.execute("UPDATE books SET available_copies=available_copies-1 WHERE id=?", (book_id,))
            self.conn.execute("""
                INSERT INTO loans(book_id,student_id,issue_date,due_date) VALUES (?,?,?,?)
            """, (book_id, student_id, issued.isoformat(), due.isoformat()))

    def return_book(self, loan_id):
        loan = self.conn.execute("""
            SELECT book_id, due_date, return_date FROM loans WHERE id=?
        """, (loan_id,)).fetchone()
        if not loan or loan["return_date"]:
            raise ValueError("This loan is not active.")
        returned = date.today()
        late_days = max(0, (returned - date.fromisoformat(loan["due_date"])).days)
        fine = late_days * FINE_PER_DAY
        with self.conn:
            self.conn.execute("UPDATE loans SET return_date=?, fine=? WHERE id=?",
                              (returned.isoformat(), fine, loan_id))
            self.conn.execute("UPDATE books SET available_copies=available_copies+1 WHERE id=?",
                              (loan["book_id"],))
        return fine

    def list_loans(self, active_only=False, search=""):
        where = []
        params = []
        if active_only:
            where.append("l.return_date IS NULL")
        if search.strip():
            p = f"%{search.strip()}%"
            where.append("(b.title LIKE ? OR s.name LIKE ? OR s.roll_no LIKE ?)")
            params.extend([p, p, p])
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        return self.conn.execute(f"""
            SELECT l.id, b.title AS book_title, s.name AS student_name, s.roll_no,
                   l.issue_date, l.due_date, l.return_date, l.fine
            FROM loans l
            JOIN books b ON b.id=l.book_id
            JOIN students s ON s.id=l.student_id
            {clause}
            ORDER BY l.id DESC
        """, params).fetchall()

    def close(self):
        self.conn.close()


class LibraryApp:
    BG = "#eef3f8"
    NAVY = "#132238"
    BLUE = "#1769aa"
    WHITE = "#ffffff"
    TEXT = "#1f2937"

    def __init__(self, root):
        self.root = root
        self.root.title("CodeWithSaadat | Library Management System")
        self.root.geometry("1180x740")
        self.root.minsize(950, 620)
        self.root.configure(bg=self.BG)
        self.db = LibraryDB()
        self.current_user = None
        self.selected_book_id = None
        self.selected_student_id = None
        self.setup_style()
        self.show_login()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background="white", foreground=self.TEXT,
                        rowheight=29, fieldbackground="white", font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#dce7f3", foreground=self.NAVY,
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#cfe6ff")], foreground=[("selected", self.TEXT)])
        style.configure("TNotebook.Tab", padding=(16, 9), font=("Segoe UI", 10, "bold"))
        style.configure("TButton", padding=(10, 7), font=("Segoe UI", 10))
        style.configure("Primary.TButton", background=self.BLUE, foreground="white")
        style.map("Primary.TButton", background=[("active", "#0f4f83")])
        style.configure("TLabel", font=("Segoe UI", 10), background=self.BG, foreground=self.TEXT)
        style.configure("TEntry", padding=6)

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear()
        outer = tk.Frame(self.root, bg=self.NAVY)
        outer.pack(fill="both", expand=True)
        card = tk.Frame(outer, bg=self.WHITE, padx=36, pady=32, highlightthickness=1,
                        highlightbackground="#d5deea")
        card.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(card, text="📚", font=("Segoe UI Emoji", 38), bg=self.WHITE).pack(pady=(0, 5))
        tk.Label(card, text="Library Management System", font=("Segoe UI", 20, "bold"),
                 bg=self.WHITE, fg=self.NAVY).pack()
        tk.Label(card, text="Administrator sign in", font=("Segoe UI", 11),
                 bg=self.WHITE, fg="#64748b").pack(pady=(5, 24))
        tk.Label(card, text="Username", bg=self.WHITE, anchor="w").pack(fill="x")
        self.login_user = ttk.Entry(card, width=34)
        self.login_user.pack(pady=(5, 14), ipady=3)
        tk.Label(card, text="Password", bg=self.WHITE, anchor="w").pack(fill="x")
        self.login_pass = ttk.Entry(card, width=34, show="•")
        self.login_pass.pack(pady=(5, 18), ipady=3)
        ttk.Button(card, text="Sign In", style="Primary.TButton", command=self.login).pack(fill="x")
        tk.Label(card, text="First-run demo: admin / Admin@123", bg=self.WHITE,
                 fg="#64748b", font=("Segoe UI", 9)).pack(pady=(16, 0))
        tk.Label(card, text="Change the demo password after signing in.",
                 bg=self.WHITE, fg="#b45309", font=("Segoe UI", 9)).pack(pady=(3, 0))
        self.login_user.focus_set()
        self.root.bind("<Return>", self.login_return)

    def login_return(self, _event=None):
        if self.root.winfo_exists() and self.current_user is None:
            self.login()

    def login(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get()
        if self.db.login(username, password):
            self.current_user = username
            self.root.unbind("<Return>")
            self.show_main()
        else:
            messagebox.showerror("Sign in failed", "Incorrect username or password.")

    def show_main(self):
        self.clear()
        header = tk.Frame(self.root, bg=self.NAVY, padx=20, pady=14)
        header.pack(fill="x")
        tk.Label(header, text="📚  Library Management System", bg=self.NAVY, fg="white",
                 font=("Segoe UI", 19, "bold")).pack(side="left")
        tk.Label(header, text=f"Admin: {self.current_user}", bg=self.NAVY, fg="#dbeafe",
                 font=("Segoe UI", 10)).pack(side="right", padx=(10, 0))
        ttk.Button(header, text="Change Password", command=self.change_password_dialog).pack(side="right")
        ttk.Button(header, text="Log Out", command=self.logout).pack(side="right", padx=8)

        self.content = tk.Frame(self.root, bg=self.BG, padx=18, pady=15)
        self.content.pack(fill="both", expand=True)
        self.notebook = ttk.Notebook(self.content)
        self.notebook.pack(fill="both", expand=True)
        self.dashboard_tab = tk.Frame(self.notebook, bg=self.BG, padx=16, pady=16)
        self.books_tab = tk.Frame(self.notebook, bg=self.BG, padx=12, pady=12)
        self.students_tab = tk.Frame(self.notebook, bg=self.BG, padx=12, pady=12)
        self.loans_tab = tk.Frame(self.notebook, bg=self.BG, padx=12, pady=12)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.books_tab, text="Books")
        self.notebook.add(self.students_tab, text="Students")
        self.notebook.add(self.loans_tab, text="Issue / Return")
        self.build_dashboard()
        self.build_books()
        self.build_students()
        self.build_loans()
        self.refresh_all()

        footer = tk.Label(self.root, text="CodeWithSaadat • Python + Tkinter + SQLite",
                          bg=self.BG, fg="#64748b", font=("Segoe UI", 9), pady=5)
        footer.pack(fill="x")

    def logout(self):
        if messagebox.askyesno("Log out", "Are you sure you want to log out?"):
            self.current_user = None
            self.show_login()

    def change_password_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Change Admin Password")
        win.configure(bg=self.BG)
        win.resizable(False, False)
        frame = tk.Frame(win, bg=self.BG, padx=20, pady=20)
        frame.pack()
        fields = []
        for label, show in [("Current password", "•"), ("New password (8+ characters)", "•"),
                            ("Confirm new password", "•")]:
            ttk.Label(frame, text=label).pack(anchor="w", pady=(8, 3))
            ent = ttk.Entry(frame, show=show, width=34)
            ent.pack(fill="x")
            fields.append(ent)

        def save():
            old, new, confirm = [x.get() for x in fields]
            if len(new) < 8:
                messagebox.showwarning("Validation", "New password must be at least 8 characters.", parent=win)
                return
            if new != confirm:
                messagebox.showwarning("Validation", "New passwords do not match.", parent=win)
                return
            if not self.db.change_password(self.current_user, old, new):
                messagebox.showerror("Password", "Current password is incorrect.", parent=win)
                return
            messagebox.showinfo("Password", "Password changed successfully.", parent=win)
            win.destroy()
        ttk.Button(frame, text="Update Password", command=save).pack(fill="x", pady=(18, 0))

    def build_dashboard(self):
        tk.Label(self.dashboard_tab, text="Library Overview", font=("Segoe UI", 22, "bold"),
                 bg=self.BG, fg=self.NAVY).pack(anchor="w", pady=(0, 14))
        self.stat_frame = tk.Frame(self.dashboard_tab, bg=self.BG)
        self.stat_frame.pack(fill="x")
        self.stat_labels = {}
        cards = [
            ("titles", "Book Titles", "#1769aa"),
            ("copies", "Total Copies", "#6d28d9"),
            ("available", "Available Copies", "#15803d"),
            ("students", "Students", "#b45309"),
            ("active", "Active Loans", "#0f766e"),
            ("overdue", "Overdue Loans", "#b91c1c"),
        ]
        for i, (key, label, color) in enumerate(cards):
            card = tk.Frame(self.stat_frame, bg="white", padx=18, pady=16,
                            highlightbackground="#dbe4ee", highlightthickness=1)
            card.grid(row=i // 3, column=i % 3, sticky="nsew", padx=6, pady=6)
            self.stat_frame.grid_columnconfigure(i % 3, weight=1)
            tk.Label(card, text=label, bg="white", fg="#64748b",
                     font=("Segoe UI", 10)).pack(anchor="w")
            value = tk.Label(card, text="0", bg="white", fg=color,
                             font=("Segoe UI", 25, "bold"))
            value.pack(anchor="w", pady=(7, 0))
            self.stat_labels[key] = value
        ttk.Button(self.dashboard_tab, text="Refresh Dashboard",
                   command=self.refresh_all).pack(anchor="w", pady=14)
        tk.Label(self.dashboard_tab,
                 text="Tip: Use the Books and Students tabs to add records before issuing a book.",
                 bg=self.BG, fg="#475569").pack(anchor="w")

    def build_books(self):
        toolbar = tk.Frame(self.books_tab, bg=self.BG)
        toolbar.pack(fill="x", pady=(0, 10))
        tk.Label(toolbar, text="Search books", bg=self.BG).pack(side="left")
        self.book_search = ttk.Entry(toolbar, width=32)
        self.book_search.pack(side="left", padx=8)
        self.book_search.bind("<KeyRelease>", lambda _e: self.refresh_books())
        ttk.Button(toolbar, text="Clear", command=lambda: (self.book_search.delete(0, "end"), self.refresh_books())).pack(side="left")
        ttk.Button(toolbar, text="New / Clear Form", command=self.clear_book_form).pack(side="right")
        ttk.Button(toolbar, text="Delete Selected", command=self.delete_book).pack(side="right", padx=6)
        ttk.Button(toolbar, text="Save / Update", style="Primary.TButton", command=self.save_book).pack(side="right", padx=6)

        form = tk.LabelFrame(self.books_tab, text="Book Details", bg=self.BG, padx=10, pady=10)
        form.pack(fill="x", pady=(0, 10))
        self.book_fields = {}
        specs = [("ISBN (optional)", "isbn"), ("Title *", "title"), ("Author *", "author"),
                 ("Category", "category"), ("Total copies *", "copies")]
        for i, (label, key) in enumerate(specs):
            r, c = divmod(i, 3)
            tk.Label(form, text=label, bg=self.BG).grid(row=r*2, column=c, sticky="w", padx=5, pady=(0, 3))
            ent = ttk.Entry(form, width=31)
            ent.grid(row=r*2+1, column=c, sticky="ew", padx=5, pady=(0, 7))
            self.book_fields[key] = ent
            form.grid_columnconfigure(c, weight=1)
        self.book_fields["category"].insert(0, "General")
        self.book_fields["copies"].insert(0, "1")

        cols = ("id", "isbn", "title", "author", "category", "total_copies", "available_copies")
        self.books_tree = self.make_tree(self.books_tab, cols, {
            "id": "ID", "isbn": "ISBN", "title": "Title", "author": "Author",
            "category": "Category", "total_copies": "Total", "available_copies": "Available"
        }, {"id": 45, "isbn": 130, "title": 230, "author": 160, "category": 130,
            "total_copies": 75, "available_copies": 85})
        self.books_tree.bind("<<TreeviewSelect>>", self.select_book)

    def clear_book_form(self):
        self.selected_book_id = None
        for key, ent in self.book_fields.items():
            ent.delete(0, "end")
        self.book_fields["category"].insert(0, "General")
        self.book_fields["copies"].insert(0, "1")
        self.books_tree.selection_remove(self.books_tree.selection())

    def select_book(self, _event=None):
        sel = self.books_tree.selection()
        if not sel:
            return
        vals = self.books_tree.item(sel[0], "values")
        self.selected_book_id = int(vals[0])
        for key, value in zip(("isbn", "title", "author", "category", "copies"),
                              (vals[1], vals[2], vals[3], vals[4], vals[5])):
            self.book_fields[key].delete(0, "end")
            self.book_fields[key].insert(0, value)

    def save_book(self):
        isbn = self.book_fields["isbn"].get().strip()
        title = self.book_fields["title"].get().strip()
        author = self.book_fields["author"].get().strip()
        category = self.book_fields["category"].get().strip() or "General"
        try:
            copies = int(self.book_fields["copies"].get())
            if not title or not author:
                raise ValueError("Title and author are required.")
            if copies < 0:
                raise ValueError("Total copies cannot be negative.")
            if self.selected_book_id:
                self.db.update_book(self.selected_book_id, isbn, title, author, category, copies)
                message = "Book updated successfully."
            else:
                self.db.add_book(isbn, title, author, category, copies)
                message = "Book added successfully."
            self.clear_book_form()
            self.refresh_all()
            messagebox.showinfo("Books", message)
        except (ValueError, sqlite3.IntegrityError) as exc:
            messagebox.showerror("Could not save book", str(exc) or "ISBN must be unique.")

    def delete_book(self):
        sel = self.books_tree.selection()
        if not sel:
            messagebox.showwarning("Select book", "Please select a book first.")
            return
        book_id = int(self.books_tree.item(sel[0], "values")[0])
        if not messagebox.askyesno("Delete book", "Delete the selected book? Historical loans prevent deletion."):
            return
        try:
            self.db.delete_book(book_id)
            self.clear_book_form()
            self.refresh_all()
        except sqlite3.IntegrityError:
            messagebox.showerror("Cannot delete", "This book has loan history. Keep the record for audit history.")

    def build_students(self):
        toolbar = tk.Frame(self.students_tab, bg=self.BG)
        toolbar.pack(fill="x", pady=(0, 10))
        tk.Label(toolbar, text="Search students", bg=self.BG).pack(side="left")
        self.student_search = ttk.Entry(toolbar, width=32)
        self.student_search.pack(side="left", padx=8)
        self.student_search.bind("<KeyRelease>", lambda _e: self.refresh_students())
        ttk.Button(toolbar, text="Clear Form", command=self.clear_student_form).pack(side="right")
        ttk.Button(toolbar, text="Delete Selected", command=self.delete_student).pack(side="right", padx=6)
        ttk.Button(toolbar, text="Save / Update", style="Primary.TButton", command=self.save_student).pack(side="right", padx=6)

        form = tk.LabelFrame(self.students_tab, text="Student Details", bg=self.BG, padx=10, pady=10)
        form.pack(fill="x", pady=(0, 10))
        self.student_fields = {}
        specs = [("Roll number *", "roll"), ("Full name *", "name"), ("Email", "email"), ("Phone", "phone")]
        for i, (label, key) in enumerate(specs):
            tk.Label(form, text=label, bg=self.BG).grid(row=0, column=i, sticky="w", padx=5, pady=(0, 3))
            ent = ttk.Entry(form, width=25)
            ent.grid(row=1, column=i, sticky="ew", padx=5)
            form.grid_columnconfigure(i, weight=1)
            self.student_fields[key] = ent
        cols = ("id", "roll_no", "name", "email", "phone", "created_at")
        self.students_tree = self.make_tree(self.students_tab, cols, {
            "id": "ID", "roll_no": "Roll No.", "name": "Student Name", "email": "Email",
            "phone": "Phone", "created_at": "Registered"
        }, {"id": 45, "roll_no": 110, "name": 180, "email": 210, "phone": 120, "created_at": 145})
        self.students_tree.bind("<<TreeviewSelect>>", self.select_student)

    def clear_student_form(self):
        self.selected_student_id = None
        for ent in self.student_fields.values():
            ent.delete(0, "end")
        self.students_tree.selection_remove(self.students_tree.selection())

    def select_student(self, _event=None):
        sel = self.students_tree.selection()
        if not sel:
            return
        vals = self.students_tree.item(sel[0], "values")
        self.selected_student_id = int(vals[0])
        for key, value in zip(("roll", "name", "email", "phone"), vals[1:5]):
            ent = self.student_fields[key]
            ent.delete(0, "end")
            ent.insert(0, value)

    def save_student(self):
        roll = self.student_fields["roll"].get().strip()
        name = self.student_fields["name"].get().strip()
        email = self.student_fields["email"].get().strip()
        phone = self.student_fields["phone"].get().strip()
        if not roll or not name:
            messagebox.showwarning("Validation", "Roll number and student name are required.")
            return
        try:
            if self.selected_student_id:
                self.db.update_student(self.selected_student_id, roll, name, email, phone)
                message = "Student updated successfully."
            else:
                self.db.add_student(roll, name, email, phone)
                message = "Student registered successfully."
            self.clear_student_form()
            self.refresh_all()
            messagebox.showinfo("Students", message)
        except sqlite3.IntegrityError:
            messagebox.showerror("Duplicate roll number", "That roll number is already registered.")

    def delete_student(self):
        sel = self.students_tree.selection()
        if not sel:
            messagebox.showwarning("Select student", "Please select a student first.")
            return
        student_id = int(self.students_tree.item(sel[0], "values")[0])
        if not messagebox.askyesno("Delete student", "Delete the selected student?"):
            return
        try:
            self.db.delete_student(student_id)
            self.clear_student_form()
            self.refresh_all()
        except sqlite3.IntegrityError:
            messagebox.showerror("Cannot delete", "This student has loan history. Keep the record for audit history.")

    def build_loans(self):
        top = tk.Frame(self.loans_tab, bg=self.BG)
        top.pack(fill="x", pady=(0, 10))
        form = tk.LabelFrame(top, text="Issue a Book", bg=self.BG, padx=10, pady=10)
        form.pack(side="left", fill="x", expand=True)
        ttk.Label(form, text="Book").grid(row=0, column=0, sticky="w", padx=5)
        ttk.Label(form, text="Student").grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(form, text="Days").grid(row=0, column=2, sticky="w", padx=5)
        self.issue_book_combo = ttk.Combobox(form, state="readonly", width=34)
        self.issue_student_combo = ttk.Combobox(form, state="readonly", width=28)
        self.issue_days = ttk.Spinbox(form, from_=1, to=90, width=6)
        self.issue_days.set("14")
        self.issue_book_combo.grid(row=1, column=0, padx=5, pady=5)
        self.issue_student_combo.grid(row=1, column=1, padx=5, pady=5)
        self.issue_days.grid(row=1, column=2, padx=5, pady=5)
        ttk.Button(form, text="Issue Book", style="Primary.TButton", command=self.issue_selected).grid(
            row=1, column=3, padx=5, pady=5)
        actions = tk.Frame(top, bg=self.BG, padx=12)
        actions.pack(side="right", fill="y")
        ttk.Button(actions, text="Return Selected Loan", command=self.return_selected).pack(fill="x", pady=(8, 6))
        ttk.Button(actions, text="Show All Loans", command=lambda: self.refresh_loans(False)).pack(fill="x")
        ttk.Button(actions, text="Show Active Only", command=lambda: self.refresh_loans(True)).pack(fill="x", pady=6)

        searchrow = tk.Frame(self.loans_tab, bg=self.BG)
        searchrow.pack(fill="x", pady=(0, 8))
        tk.Label(searchrow, text="Search by book, student or roll number", bg=self.BG).pack(side="left")
        self.loan_search = ttk.Entry(searchrow, width=34)
        self.loan_search.pack(side="left", padx=8)
        self.loan_search.bind("<KeyRelease>", lambda _e: self.refresh_loans(self.active_only))
        self.active_only = False
        cols = ("id", "book_title", "student_name", "roll_no", "issue_date", "due_date", "return_date", "fine")
        self.loans_tree = self.make_tree(self.loans_tab, cols, {
            "id": "Loan ID", "book_title": "Book", "student_name": "Student", "roll_no": "Roll No.",
            "issue_date": "Issue Date", "due_date": "Due Date", "return_date": "Return Date", "fine": "Fine"
        }, {"id": 65, "book_title": 210, "student_name": 160, "roll_no": 105,
            "issue_date": 100, "due_date": 100, "return_date": 105, "fine": 70})

    def issue_selected(self):
        books = getattr(self, "book_options", [])
        students = getattr(self, "student_options", [])
        bidx = self.issue_book_combo.current()
        sidx = self.issue_student_combo.current()
        if bidx < 0 or sidx < 0:
            messagebox.showwarning("Missing selection", "Select an available book and a student.")
            return
        try:
            days = int(self.issue_days.get())
            if not 1 <= days <= 90:
                raise ValueError("Loan duration must be between 1 and 90 days.")
            self.db.issue_book(books[bidx][0], students[sidx][0], days)
            self.refresh_all()
            messagebox.showinfo("Book issued", f"Book issued successfully. Due date: {(date.today()+timedelta(days=days)).isoformat()}")
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror("Could not issue book", str(exc))

    def return_selected(self):
        sel = self.loans_tree.selection()
        if not sel:
            messagebox.showwarning("Select loan", "Select an active loan first.")
            return
        vals = self.loans_tree.item(sel[0], "values")
        if vals[6]:
            messagebox.showinfo("Already returned", "This loan has already been returned.")
            return
        if not messagebox.askyesno("Return book", f"Mark '{vals[1]}' as returned?"):
            return
        try:
            fine = self.db.return_book(int(vals[0]))
            self.refresh_all()
            if fine:
                messagebox.showinfo("Returned", f"Book returned. Late fine: {fine} ({FINE_PER_DAY} per late day).")
            else:
                messagebox.showinfo("Returned", "Book returned successfully. No late fine.")
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror("Could not return book", str(exc))

    def make_tree(self, parent, columns, headings, widths):
        wrapper = tk.Frame(parent, bg=self.BG)
        wrapper.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrapper, columns=columns, show="headings", selectmode="browse")
        yscroll = ttk.Scrollbar(wrapper, orient="vertical", command=tree.yview)
        xscroll = ttk.Scrollbar(wrapper, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        wrapper.rowconfigure(0, weight=1)
        wrapper.columnconfigure(0, weight=1)
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=widths.get(col, 120), minwidth=50, anchor="w")
        return tree

    @staticmethod
    def fill_tree(tree, rows):
        tree.delete(*tree.get_children())
        for row in rows:
            tree.insert("", "end", values=tuple(row))

    def refresh_books(self):
        self.fill_tree(self.books_tree, [
            (r["id"], r["isbn"] or "", r["title"], r["author"], r["category"],
             r["total_copies"], r["available_copies"])
            for r in self.db.list_books(self.book_search.get())
        ])

    def refresh_students(self):
        self.fill_tree(self.students_tree, [
            (r["id"], r["roll_no"], r["name"], r["email"] or "", r["phone"] or "", r["created_at"])
            for r in self.db.list_students(self.student_search.get())
        ])

    def refresh_loans(self, active_only=None):
        if active_only is not None:
            self.active_only = active_only
        rows = self.db.list_loans(self.active_only, self.loan_search.get())
        self.fill_tree(self.loans_tree, [
            (r["id"], r["book_title"], r["student_name"], r["roll_no"], r["issue_date"],
             r["due_date"], r["return_date"] or "—", r["fine"])
            for r in rows
        ])

    def refresh_issue_combos(self):
        self.book_options = [
            (r["id"], r["title"], r["available_copies"])
            for r in self.db.list_books() if r["available_copies"] > 0
        ]
        self.student_options = [(r["id"], r["roll_no"], r["name"]) for r in self.db.list_students()]
        self.issue_book_combo["values"] = [
            f'{b[1]} (available: {b[2]})' for b in self.book_options
        ]
        self.issue_student_combo["values"] = [
            f"{s[1]} — {s[2]}" for s in self.student_options
        ]
        if self.book_options and self.issue_book_combo.current() < 0:
            self.issue_book_combo.current(0)
        if self.student_options and self.issue_student_combo.current() < 0:
            self.issue_student_combo.current(0)

    def refresh_all(self):
        stats = self.db.stats()
        for key, value in stats.items():
            self.stat_labels[key].configure(text=str(value))
        self.refresh_books()
        self.refresh_students()
        self.refresh_issue_combos()
        self.refresh_loans(self.active_only)

    def on_close(self):
        try:
            self.db.close()
        finally:
            self.root.destroy()


def main():
    root = tk.Tk()
    LibraryApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
