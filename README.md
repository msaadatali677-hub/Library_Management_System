# Python Library Management System

A desktop Library Management System built with Python, Tkinter and SQLite.

## Features
- Admin login with salted PBKDF2-HMAC-SHA256 password hashes
- Change admin password
- Dashboard statistics: book titles, copies, availability, students, active loans and overdue loans
- Add, edit, search and delete books
- Register, edit, search and delete students
- Issue and return books with due dates
- Automatic late-fine calculation
- Input validation, unique ISBN/roll number, foreign keys and protected loan history
- Sample books and students are inserted automatically on first run

## Requirements
- Python 3.10 or later recommended
- Tkinter (normally included with standard Python installers)
- No pip packages required

## Run
1. Extract the ZIP archive.
2. Open a terminal in the `library_management_system` folder.
3. Run:

   ```bash
   python main.py
   ```

   On some systems, use `python3 main.py`.

4. Sign in with the first-run demo account:
   - Username: `admin`
   - Password: `Admin@123`
5. Immediately use **Change Password** to set your own password.

The SQLite database is created automatically at `data/library.db`. Keep this file to preserve your records. Back it up regularly.

## Sample data
The first run inserts:
- Books: Clean Code, Effective Java, Head First Design Patterns, Fluent Python, Introduction to Algorithms
- Students: Ali Ahmed (BSCS-001), Ayesha Khan (BSCS-002), Usman Raza (BSCS-003)

Seed data is inserted only when the relevant table is empty.

## Business rules
- Default loan period is 14 days (can be changed for each issue, 1–90 days).
- Fine is 20 currency units per overdue day. Change `FINE_PER_DAY` in `main.py` if your institution uses another rate.
- The app does not allow a student to have two active loans for the same book.
- A book or student with loan history cannot be deleted, preserving transaction history.
- Reducing total book copies below the number currently loaned is blocked.

## Folder structure
```text
library_management_system/
├── main.py
├── README.md
└── data/
    └── library.db   # generated automatically on first run
```

## Notes
This is a local single-computer academic project, not a multi-user network system. The default credentials are demo credentials and must be changed before real use. Back up the database file before moving or updating the project.
