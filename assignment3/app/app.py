from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from auth import generate_secret, generate_qr_code, verify_totp
from db import init_user_db, register_user, login_user, get_secret_for_user
from authlib.integrations.flask_client import OAuth
from db import save_oauth_tokens


app = Flask(__name__)
app.secret_key = 'supersecretkey'  # In a production app, this should be a more secure and hidden key
app.debug = False

# Sett inn klient ID og klienthemmelighet
app.config['GOOGLE_CLIENT_ID'] = '606232351646-2sjtlbnm09n9os7aqamfqi1ce3g6k0rb.apps.googleusercontent.com'
app.config['GOOGLE_CLIENT_SECRET'] = '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'

# OAuth2 Konfigurasjon
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs', 
)



DATABASE = 'database/site_data.db'


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create posts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

    # Initialize the user table from db.py
    init_user_db()

init_db()

# Legg til OAuth2 Ruter
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('authorize', _external=True)
    print("Redirect URI:", redirect_uri)  # Denne linjen vil skrive ut den faktiske URL-en
    return google.authorize_redirect(redirect_uri)


""" @app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    # Behandle brukerens informasjon her (f.eks. logg inn brukeren)
    return redirect(url_for('index'))  # Eller en annen passende rute

 """
@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()

    email = user_info.get('email')
    if email:
        # Lagre brukerens e-post og OAuth-tokens i databasen
        access_token = token.get('access_token')
        refresh_token = token.get('refresh_token')
        expires_in = token.get('expires_in')  # Beregn utløpstidspunktet
        
        # Sjekk om brukeren allerede finnes i databasen
        if not get_secret_for_user(email):
            # Registrer brukeren i databasen hvis de ikke finnes
            secret = generate_secret()  # Generer et hemmelig nøkkel for 2FA
            register_user(email, '', secret)  # Her kan du vurdere å lagre et dummy-passord eller tilpasse funksjonen

        # Oppdater OAuth-tokens i databasen
        save_oauth_tokens(email, access_token, refresh_token, expires_in)

    # Logg inn brukeren og omdiriger til en passende side
    session['username'] = email
    return redirect(url_for('index'))


@app.route('/')
def index():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM posts ORDER BY id DESC')
    posts = cursor.fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route('/post', methods=['POST'])
def post():
    title = request.form['title']
    content = request.form['content']
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO posts (title, content) VALUES (?, ?)', (title, content))
    conn.commit()
    conn.close()
    flash('Post added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        secret = generate_secret()  # Generate a secret for TOTP
        if register_user(username, password, secret):  # Modify the register_user function to accept and save the secret
            qr_code = generate_qr_code(secret, username)  # Generate a QR code for the user to scan
            flash('Registration successful! Please scan the QR code with your 2FA app.', 'success')
            return render_template('register.html', qr_code=qr_code)
        else:
            flash('Registration failed.', 'danger')
            return render_template('register.html')
    else:
        return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            totp = request.form.get('totp')  # Retrieve the TOTP provided by the user
            
            secret = get_secret_for_user(username)
            if not secret:
                flash('Login failed. User not found or no 2FA setup.', 'danger')
                return render_template('login.html')
            
            login_result = login_user(username, password) # Storing the result in a variable for clarity

            if login_result == "success" and verify_totp(totp, secret): # Explicitly check for "success"
                flash('Logged in successfully!', 'success')
                session['username'] = username
                return redirect(url_for('index'))
            elif login_result == "locked_out":
                flash('Account locked due to multiple failed attempts. Please try again later.', 'danger')
                return render_template('login.html')
            else:
                flash('Login failed. Check your credentials and 2FA code.', 'danger')
                return render_template('login.html')
        else:
            return render_template('login.html')
    except Exception as e:
        # Log the error for debugging
        print(e)
        flash('An error occurred:  ' + str(e) + '.  Please try again.', 'danger')
        return render_template('index.html')  

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

