import sqlite3
import bcrypt

DATABASE = 'database/site_data.db'

def init_user_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        attempt_count INTEGER DEFAULT 0,
        last_attempt_time INTEGER DEFAULT 0
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

def login_user(username: str, password: str) -> str:
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, attempt_count, last_attempt_time FROM users WHERE username=?', (username,))
    data = cursor.fetchone()

    if data:
        stored_hash, attempt_count, last_attempt_time = data
        current_time = int(time.time())

        if attempt_count >= 3 and current_time - last_attempt_time < 600:
            conn.close()
            return "locked_out"

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            cursor.execute('UPDATE users SET attempt_count = 0 WHERE username=?', (username,))
            conn.commit()
            conn.close()
            return "success"
        else:
            new_attempt_count = attempt_count + 1
            cursor.execute('UPDATE users SET attempt_count = ?, last_attempt_time = ? WHERE username=?', (new_attempt_count, current_time, username))
            conn.commit()
            conn.close()
            return "failed"
    else:
        conn.close()
        return "failed"


