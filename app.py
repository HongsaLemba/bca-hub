import os
import sqlite3
from flask import Flask, request, session, redirect, send_from_directory, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# --- 1. CLOUD-READY CONFIGURATION ---
# Use a secure environment variable for the key on Render; fallback for local testing
app.secret_key = os.environ.get('SECRET_KEY', 'bca_super_secret_key')

# Set up the Database path to use a persistent 'data' folder for cloud hosting
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# This works on Render's free tier
DB_PATH = os.path.join(BASE_DIR, 'users.db')

# --- 2. INITIALIZE SQLITE DATABASE ---
def init_db():

        
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
init_db()

# --- 3. THE SECURITY DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect('/login.html')
        return f(*args, **kwargs)
    return decorated_function

# --- 4. AUTHENTICATION ROUTES ---
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    hashed_pw = generate_password_hash(password)
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                         (username, email, hashed_pw))
        session['logged_in'] = True
        session['username'] = username
        return redirect('/') 
    except sqlite3.IntegrityError:
        return redirect('/login.html?error=email_taken')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute('SELECT username, password FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user[1], password):
            session['logged_in'] = True
            session['username'] = user[0]
            return redirect('/')
        else:
            return redirect('/login.html?error=invalid_credentials')

@app.route('/guest')
def guest():
    session['logged_in'] = True
    session['username'] = 'Guest'
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login.html')

# --- 5. PROTECTED PAGE ROUTES ---
@app.route('/')
@login_required
def home():
    return send_from_directory(BASE_DIR, 'project.html')

@app.route('/<path:filename>')
def serve_files(filename):
    if filename.endswith(('.css', '.png', '.jpg', '.gif')):
        return send_from_directory(BASE_DIR, filename)
    
    if filename == 'login.html':
        return send_from_directory(BASE_DIR, filename)
        
    if 'logged_in' not in session:
        return redirect(url_for('serve_files', filename='login.html'))
        
    return send_from_directory(BASE_DIR, filename)

@app.route('/download/<int:semester>/<string:filename>')
@login_required
def download_note(semester, filename):
    folder_name = f'Semester_{semester}'
    semester_dir = os.path.join(BASE_DIR, folder_name)
    if not os.path.exists(os.path.join(semester_dir, filename)):
        return "File not found", 404
    return send_from_directory(semester_dir, filename, as_attachment=True)

if __name__ == '__main__':
    # Local debug remains True, but on Render, Gunicorn will handle the run
    app.run(debug=True)