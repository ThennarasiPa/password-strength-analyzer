# Password Strength Analyzer with History Tracking (Cybersecurity Project)

import re
import secrets
import string
import sqlite3
import hashlib
from datetime import datetime
import getpass

# ==========================================
# DATABASE CONFIGURATION
# ==========================================
DB_NAME = "password_vault.db"


def init_database():
    """Create database table if not exists."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        conn.commit()


def hash_password(password):
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def is_password_reused(username, password):
    """Check if password was used before."""
    target_hash = hash_password(password)

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT created_at FROM password_history WHERE username=? AND password_hash=?",
            (username.lower(), target_hash)
        )
        return cursor.fetchone()  # None or (timestamp,)


def record_password(username, password):
    """Store password hash in DB."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO password_history (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username.lower(), hash_password(password), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()


# ==========================================
# PASSWORD ANALYZER
# ==========================================
def analyze_strength(password, username=""):
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append(" Must be at least 8 characters (12+ recommended).")

    # Complexity checks
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append(" Add lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append(" Add uppercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append(" Add numbers.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>_+\-\[\]\\/`~;=]", password):
        score += 2
    else:
        feedback.append(" Add special characters.")

    # Weak patterns
    weak_patterns = ["123", "abc", "qwerty", "password"]

    if username and username.lower() in password.lower():
        score = max(0, score - 2)
        feedback.append(" Avoid using your username.")

    if any(p in password.lower() for p in weak_patterns):
        score = max(0, score - 1)
        feedback.append(" Avoid common patterns (123, abc, password).")

    score = max(0, min(score, 5))
    return score, feedback


# ==========================================
# SECURE PASSWORD GENERATOR
# ==========================================
def generate_password(length=14):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    specials = "!@#$%^&*_-+="

    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(specials)
    ]

    all_chars = lowercase + uppercase + digits + specials
    password += [secrets.choice(all_chars) for _ in range(length - 4)]

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


# ==========================================
# MAIN PROGRAM
# ==========================================
def main():
    init_database()

    print("\n" + "=" * 55)
    print("      PASSWORD STRENGTH ANALYZER TOOL")
    print("=" * 55)

    username = input("Enter username: ").strip()
    if not username:
        print(" Username cannot be empty.")
        return

    password = getpass.getpass("Enter password: ")

    print("\n" + "-" * 55)

    # Check reuse
    reuse_data = is_password_reused(username, password)

    if reuse_data:
        print(" PASSWORD REUSE DETECTED!")
        print(f" Last used on: {reuse_data[0]}")

    score, feedback = analyze_strength(password, username)

    # Strength evaluation
    if score >= 4:
        print("\n Strength: STRONG")
        if not reuse_data:
            record_password(username, password)
            print(" Password stored securely.")
    elif score >= 2:
        print("\n Strength: MEDIUM")
    else:
        print("\n Strength: WEAK")

    # Feedback
    if feedback:
        print("\n Suggestions:")
        for item in feedback:
            print(" -", item)

    # Suggest strong password
    print("\n Suggested Strong Password:")
    print(generate_password())

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()
