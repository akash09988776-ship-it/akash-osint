import os, sqlite3, secrets, requests
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE, 'akash.db')
UPLOAD_DIR = os.path.join(BASE, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a2027')
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'akash@gmail.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'akash@2027')

API_URL = "https://akash-number-lookup.vercel.app/v4/lookup-z8f9k1"
API_KEY = "DEMO"

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def generate_user_id():
    return str(secrets.randbelow(900000000000) + 100000000000)

@app.context_processor
def inject_user():
    me = None
    if session.get('user_id') and session.get('role') != 'admin':
        with db() as c:
            me = c.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    return {'me': me, 'is_admin': session.get('role') == 'admin'}

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get('user_id'): return redirect(url_for('login'))
        return fn(*a, **kw)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if session.get('role') != 'admin': abort(403)
        return fn(*a, **kw)
    return wrapper

@app.route('/logo.png')
def serve_logo(): return send_from_directory(BASE, 'logo.png')

@app.route('/manifest.json')
def serve_manifest(): return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def serve_sw(): return send_from_directory('static', 'sw.js')

@app.route('/')
def home():
    if not session.get('user_id'): return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or len(password) < 8:
            flash('Please fill all fields. Password must be 8+ chars.')
            return redirect('/register')
        with db() as c:
            try:
                c.execute('INSERT INTO users (public_id, name, username, password_hash, role) VALUES (?,?,?,?,?)', 
                          (generate_user_id(), name, email, generate_password_hash(password), 'user'))
                flash('Account created. Login now.')
                return redirect('/login')
            except sqlite3.IntegrityError:
                flash('Email already registered.')
                return redirect('/register')
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if email == ADMIN_EMAIL.lower() and secrets.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session['role'] = 'admin'
            session.permanent = True
            return redirect('/admin')
            
        with db() as c:
            user = c.execute('SELECT * FROM users WHERE username=?', (email,)).fetchone()
            if user and check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = user['id']
                session['role'] = user['role']
                session.permanent = True
                return redirect('/dashboard')
        flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    result = None
    if request.method == 'POST':
        number = ''.join(ch for ch in request.form.get('number','') if ch.isdigit())
        if len(number) != 10:
            flash('10 digit number required.')
        else:
            try:
                res = requests.get(f"{API_URL}?key={API_KEY}&query={number}", timeout=20)
                data = res.json()
                if 'error' in data: flash(data['error'])
                else: result = data
            except Exception as e: flash('API Error: ' + str(e))
    return render_template('dashboard.html', result=result)

@app.route('/profile/photo', methods=['POST'])
@login_required
def profile_photo():
    f = request.files.get('photo')
    if not f or not f.filename: return redirect(request.referrer or url_for('dashboard'))
    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in ('.png','.jpg','.jpeg','.webp'): return redirect(request.referrer or url_for('dashboard'))
    name = f"user_{session['user_id']}{ext}"
    f.save(os.path.join(UPLOAD_DIR, name))
    with db() as c:
        c.execute('UPDATE users SET photo=? WHERE id=?', (name, session['user_id']))
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/admin')
@admin_required
def admin():
    with db() as c:
        users = c.execute('SELECT * FROM users ORDER BY id DESC').fetchall()
        unread = c.execute("SELECT COUNT(*) n FROM private_messages WHERE sender='user' AND is_read=0").fetchone()['n']
    return render_template('admin.html', users=users, unread=unread)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
