import secrets
import string
import bcrypt
import sqlite3


# Generate Secure Password
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))


# Hash Password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


# Initialize SQLite Database
def init_db():
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()


# Store Password in Database
def store_password(username, password):
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Username already exists!")
    finally:
        conn.close()


# Fetch Stored Password
def fetch_password(username):
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


# Verify Input Password
def verify_password(username, input_password):
    stored_hash = fetch_password(username)
    if stored_hash and bcrypt.checkpw(input_password.encode(), stored_hash.encode()):
        return True
    return False


if __name__ == "__main__":
    init_db()
    print("Password Manager Initialized!")

    test_username = "user@example.com"
    test_password = generate_password()

    print(f"Generated password for {test_username}: {test_password}")
    store_password(test_username, test_password)

    if verify_password(test_username, test_password):
        print("Password verification successful!")
    else:
        print("Password verification failed!")
