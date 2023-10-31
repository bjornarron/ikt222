import sqlite3
import bcrypt

DATABASE = 'database/site_data.db'

def init_user_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create a table for users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def register_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # This error occurs if the username is already taken
        print("Username already exists!")
        return False
    finally:
        conn.close()

def login_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    data = cursor.fetchone()
    conn.close()
    if data:
        stored_hash = data[0]
        return check_password(password, stored_hash)
    else:
        return False
