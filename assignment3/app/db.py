import sqlite3
import bcrypt

conn = sqlite3.connect('user_data.db')
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



def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def register_user(username: str, password: str) -> bool:
    try:
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # This error occurs if the username is already taken
        print("Username already exists!")
        return False

def login_user(username: str, password: str) -> bool:
    cursor.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    data = cursor.fetchone()
    if data:
        stored_hash = data[0]
        return check_password(password, stored_hash)
    else:
        return False