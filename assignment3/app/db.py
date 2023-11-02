import sqlite3
import bcrypt
import time
import sqlite3

from auth import get_user_email

from cryptography.fernet import Fernet
key = Fernet.generate_key()
with open('secret.key', 'wb') as key_file:
    key_file.write(key)

def load_key():
    with open('secret.key', 'rb') as key_file:
        return key_file.read()

# Legger til opprettelse av Fernet-nøkkelen
cipher_suite = Fernet(load_key())

def encrypt_token(token):
    return cipher_suite.encrypt(token.encode())

def decrypt_token(encrypted_token):
    return cipher_suite.decrypt(encrypted_token).decode()
 
DATABASE = 'database/site_data.db'

def init_user_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        secret TEXT NOT NULL,
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

def register_user(username: str, password: str, secret: str) -> bool:
    conn = sqlite3.connect(DATABASE)  # Initiate the connection
    cursor = conn.cursor()
    try:
        hashed_password = hash_password(password)
        cursor.execute(
            'INSERT INTO users (username, password_hash, secret) VALUES (?, ?, ?)', 
            (username, hashed_password, secret)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print("Username already exists!")
        conn.close()
        return False

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

def get_secret_for_user(username: str) -> str:
    conn = sqlite3.connect(DATABASE)
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT secret FROM users WHERE username=?', (username,))
            data = cursor.fetchone()
            if data:
                return data[0]
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    return None



# Her følger de oppdaterte funksjonene med kryptering


def get_oauth_tokens(email):
    conn = sqlite3.connect('database/google_account.db')
    cursor = conn.cursor()
    cursor.execute('SELECT access_token, refresh_token, token_expires FROM oauth_tokens WHERE email = ?', (email,))
    data = cursor.fetchone()
    conn.close()

    if data:
        encrypted_access_token, encrypted_refresh_token, token_expires = data
        access_token = decrypt_token(encrypted_access_token)
        refresh_token = decrypt_token(encrypted_refresh_token)
        return access_token, refresh_token, token_expires
    return None

def update_access_token(email, new_access_token, new_expires):
    conn = sqlite3.connect('database/google_account.db')
    cursor = conn.cursor()
    encrypted_access_token = encrypt_token(new_access_token)

    cursor.execute('''
        UPDATE oauth_tokens
        SET access_token = ?, token_expires = ?
        WHERE email = ?;
    ''', (encrypted_access_token, new_expires, email))
    conn.commit()
    conn.close()


#tabell for google account
def init_google_account_db():
    conn = sqlite3.connect('database/google_account.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS oauth_tokens (
        email TEXT PRIMARY KEY,
        access_token TEXT,
        refresh_token TEXT,
        token_expires TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()

def save_oauth_tokens(email, access_token, refresh_token, token_expires):
    conn = sqlite3.connect('database/google_account.db')
    cursor = conn.cursor()

    encrypted_access_token = encrypt_token(access_token)
    encrypted_refresh_token = encrypt_token(refresh_token) if refresh_token is not None else None

    cursor.execute('''
        INSERT INTO oauth_tokens (email, access_token, refresh_token, token_expires) 
        VALUES (?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET 
        access_token = excluded.access_token,
        refresh_token = excluded.refresh_token,
        token_expires = excluded.token_expires;
    ''', (email, encrypted_access_token, encrypted_refresh_token, token_expires))
    conn.commit()
    conn.close()



# Kall funksjonen for å initialisere Google Account databasen
init_google_account_db()


