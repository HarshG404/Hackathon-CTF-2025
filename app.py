"""
ICSS India - CTF Web Application
Enterprise-Grade Flask Application with Embedded Security Vulnerabilities
Author: CTF Challenge Designer
Version: 2.0 - Per-User Isolated Environment

Each logged-in student gets their own isolated environment:
- Reviews/comments are stored per user session (not shared)
- Flags are tracked per user
- Flag popups appear on vulnerability discovery
- Side panel shows found flags
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, make_response
from flask import Response, abort, send_from_directory
import sqlite3
import hashlib
import os
import time
import base64
import jwt
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from functools import wraps
import json
import subprocess
import pickle
import re
import uuid

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345'  # VULN: Weak secret key (hardcoded)
app.config['DEBUG'] = False

# Database configuration
DATABASE = 'icss_ctf.db'

# JWT Configuration - VULN: Weak JWT secret
JWT_SECRET = 'jwt_secret_123'
JWT_ALGORITHM = 'HS256'

# Flag storage - Each vulnerability has a unique flag
FLAGS = {
    'sql_injection':            'FLAG{SQL_1nj3ct10n_M4st3r_2024}',
    'blind_sqli':               'FLAG{Bl1nd_SQL_T1m3_B4s3d_Pwn}',
    'xss_reflected':            'FLAG{R3fl3ct3d_XSS_V1ct0ry}',
    'xss_stored':               'FLAG{St0r3d_XSS_P3rs1st3nt}',
    'command_injection':        'FLAG{C0mm4nd_1nj3ct10n_Sh3ll}',
    'file_upload':              'FLAG{F1l3_Upl04d_Byp4ss_2024}',
    'lfi':                      'FLAG{L0c4l_F1l3_1nclus10n_R34d}',
    'idor':                     'FLAG{1D0R_4cc3ss_C0ntr0l_F41l}',
    'broken_auth':              'FLAG{Br0k3n_4uth_W34k_P4ss}',
    'jwt_none':                 'FLAG{JWT_4lg_N0n3_Byp4ss}',
    'jwt_weak':                 'FLAG{JWT_W34k_S3cr3t_Cr4ck3d}',
    'session_fixation':         'FLAG{S3ss10n_F1x4t10n_H4ck}',
    'xxe':                      'FLAG{XXE_Ext3rn4l_3nt1ty_P4rs3d}',
    'ssti':                     'FLAG{S3rv3r_S1d3_T3mpl4t3_1nj}',
    'path_traversal':           'FLAG{P4th_Tr4v3rs4l_D1r3ct0ry}',
    'exposed_git':              'FLAG{3xp0s3d_G1t_R3p0_S3cr3t}',
    'exposed_env':              'FLAG{3nv_F1l3_L34k3d_K3ys}',
    'debug_mode':               'FLAG{D3bug_M0d3_St4ck_Tr4c3}',
    'directory_listing':        'FLAG{D1r3ct0ry_L1st1ng_3n4bl3d}',
    'weak_hash':                'FLAG{W34k_H4sh_MD5_Cr4ck3d}',
    'hardcoded_secret':         'FLAG{H4rdc0d3d_S3cr3t_F0und}',
    'insecure_deserialization': 'FLAG{1ns3cur3_D3s3r14l1z4t10n}',
    'open_redirect':            'FLAG{0p3n_R3d1r3ct_Ph1sh1ng}',
    'cors_misconfiguration':    'FLAG{C0RS_M1sc0nf1g_3xpl01t}',
    'csrf':                     'FLAG{CSRF_T0k3n_M1ss1ng_Pwn}',
    'api_exposure':             'FLAG{4P1_S3ns1t1v3_D4t4_L34k}',
    'rate_limit':               'FLAG{N0_R4t3_L1m1t_Brut3_F0rc3}',
    'privilege_escalation':     'FLAG{Pr1v1l3g3_3sc4l4t10n_4dm1n}',
    'info_disclosure':          'FLAG{1nf0_D1scl0sur3_L0gs_L34k}',
    'robots_txt':               'FLAG{R0b0ts_Txt_S3cr3t_P4th}',
    'html_comment':             'FLAG{HTML_C0mm3nt_H1dd3n_Fl4g}',
    'js_source':                'FLAG{J4v4Scr1pt_S0urc3_3xp0s3d}',
    'backup_file':              'FLAG{B4ckup_F1l3_D0wnl04d3d}',
}

FLAG_LABELS = {
    'sql_injection':            'SQL Injection',
    'blind_sqli':               'Blind SQL Injection',
    'xss_reflected':            'Reflected XSS',
    'xss_stored':               'Stored XSS',
    'command_injection':        'Command Injection',
    'file_upload':              'File Upload Bypass',
    'lfi':                      'Local File Inclusion',
    'idor':                     'IDOR',
    'broken_auth':              'Broken Authentication',
    'jwt_none':                 'JWT Algorithm None',
    'jwt_weak':                 'JWT Weak Secret',
    'session_fixation':         'Session Fixation',
    'xxe':                      'XXE',
    'ssti':                     'Server-Side Template Injection',
    'path_traversal':           'Path Traversal',
    'exposed_git':              'Exposed Git Repo',
    'exposed_env':              'Exposed .env File',
    'debug_mode':               'Debug Mode Stack Trace',
    'directory_listing':        'Directory Listing',
    'weak_hash':                'Weak MD5 Hash',
    'hardcoded_secret':         'Hardcoded Secret',
    'insecure_deserialization': 'Insecure Deserialization',
    'open_redirect':            'Open Redirect',
    'cors_misconfiguration':    'CORS Misconfiguration',
    'csrf':                     'CSRF',
    'api_exposure':             'API Sensitive Data Exposure',
    'rate_limit':               'No Rate Limiting',
    'privilege_escalation':     'Privilege Escalation',
    'info_disclosure':          'Information Disclosure',
    'robots_txt':               'robots.txt Exposure',
    'html_comment':             'HTML Comment Leak',
    'js_source':                'JavaScript Source Exposure',
    'backup_file':              'Backup File Download',
}

# ==================== PER-USER FLAG TRACKING ====================

def award_flag(flag_key):
    """Award a flag to the current user's session and return flag value."""
    if 'found_flags' not in session:
        session['found_flags'] = {}
    if flag_key not in session['found_flags']:
        session['found_flags'][flag_key] = {
            'value': FLAGS[flag_key],
            'label': FLAG_LABELS.get(flag_key, flag_key),
            'time': datetime.now().strftime('%H:%M:%S')
        }
        session.modified = True
    return FLAGS[flag_key]

def get_found_flags():
    """Return list of flags found by this user."""
    return session.get('found_flags', {})

def set_pending_flag(flag_key):
    """Queue a flag popup for next page load."""
    session['pending_flag'] = {
        'key': flag_key,
        'value': FLAGS[flag_key],
        'label': FLAG_LABELS.get(flag_key, flag_key)
    }
    session.modified = True
    award_flag(flag_key)

def pop_pending_flag():
    """Get and clear pending flag popup."""
    flag = session.pop('pending_flag', None)
    session.modified = True
    return flag

# ==================== PER-USER REVIEW STORAGE ====================

def get_user_reviews_key(course_id):
    """Session key for per-user reviews."""
    return f'reviews_{course_id}'

def get_user_reviews(course_id):
    """Get reviews only for the current user's session."""
    key = get_user_reviews_key(course_id)
    return session.get(key, [])

def add_user_review(course_id, rating, comment):
    """Store a review in the current user's session only."""
    key = get_user_reviews_key(course_id)
    if key not in session:
        session[key] = []
    username = session.get('username', 'Anonymous')
    session[key].append({
        'username': username,
        'rating': int(rating),
        'comment': comment,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M')
    })
    session.modified = True

# ==================== DATABASE FUNCTIONS ====================

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database with vulnerable data"""
    db = get_db()

    db.execute('DROP TABLE IF EXISTS users')
    db.execute('DROP TABLE IF EXISTS courses')
    db.execute('DROP TABLE IF EXISTS enrollments')
    db.execute('DROP TABLE IF EXISTS invoices')
    db.execute('DROP TABLE IF EXISTS logs')
    db.execute('DROP TABLE IF EXISTS messages')

    # Users - VULN: MD5 weak hashing
    db.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reset_token TEXT,
            session_id TEXT
        )
    ''')

    db.execute('''
        CREATE TABLE courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            duration TEXT,
            instructor TEXT,
            category TEXT
        )
    ''')

    db.execute('''
        CREATE TABLE enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            course_id INTEGER,
            enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        )
    ''')

    # Invoices - VULN: IDOR
    db.execute('''
        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            course_id INTEGER,
            amount REAL,
            flag_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Logs - VULN: Info disclosure
    db.execute('''
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_type TEXT,
            message TEXT,
            flag_hint TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    db.execute('''
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            subject TEXT,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Insert users - VULN: Default credentials + MD5
    users = [
        ('admin',      hashlib.md5('password123'.encode()).hexdigest(),     'admin@icss.edu',      'admin'),
        ('instructor', hashlib.md5('instructor@2024'.encode()).hexdigest(), 'instructor@icss.edu', 'instructor'),
        ('student1',   hashlib.md5('student123'.encode()).hexdigest(),      'student1@icss.edu',   'student'),
        ('testuser',   hashlib.md5('test1234'.encode()).hexdigest(),        'test@icss.edu',       'student'),
        ('guest',      hashlib.md5('guest'.encode()).hexdigest(),           'guest@icss.edu',      'student'),
        ('flaguser',   hashlib.md5('hidden_flag_user'.encode()).hexdigest(),'flag@icss.edu',       'admin'),
    ]
    for username, password, email, role in users:
        db.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                   (username, password, email, role))

    courses = [
        ('Generative AI & Machine Learning', 'Master AI technologies including ChatGPT, DALL-E, and ML algorithms', 45000, '6 months', 'Dr. Priya Sharma', 'AI'),
        ('Advanced Cyber Security', 'Become a certified security professional with hands-on penetration testing', 55000, '8 months', 'Mr. Rajesh Kumar', 'Security'),
        ('Cloud Computing Masters', 'AWS, Azure, and GCP certification preparation with practical labs', 40000, '5 months', 'Ms. Anita Singh', 'Cloud'),
        ('Full Stack Web Development', 'Complete web development from frontend to backend with MERN stack', 35000, '6 months', 'Mr. Vikram Patel', 'Development'),
        ('Data Science & Analytics', 'Python, R, and advanced analytics with real-world projects', 50000, '7 months', 'Dr. Suresh Reddy', 'Data Science'),
        ('DevOps Engineering', 'CI/CD, Docker, Kubernetes, and infrastructure as code', 42000, '6 months', 'Mr. Amit Gupta', 'DevOps'),
    ]
    for name, desc, price, duration, instructor, category in courses:
        db.execute('INSERT INTO courses (name, description, price, duration, instructor, category) VALUES (?, ?, ?, ?, ?, ?)',
                   (name, desc, price, duration, instructor, category))

    # Enrollments
    db.execute('INSERT INTO enrollments (user_id, course_id) VALUES (3, 1)')
    db.execute('INSERT INTO enrollments (user_id, course_id) VALUES (3, 2)')
    db.execute('INSERT INTO enrollments (user_id, course_id) VALUES (4, 1)')

    # Invoices - VULN: Admin invoice #1 has flag (IDOR)
    invoices = [
        (1, 1, 45000, FLAGS['idor']),
        (3, 1, 45000, ''),
        (3, 2, 55000, ''),
        (4, 1, 45000, ''),
    ]
    for user_id, course_id, amount, flag_data in invoices:
        db.execute('INSERT INTO invoices (user_id, course_id, amount, flag_data) VALUES (?, ?, ?, ?)',
                   (user_id, course_id, amount, flag_data))

    # Logs - VULN: Info disclosure
    db.execute('INSERT INTO logs (log_type, message, flag_hint) VALUES (?, ?, ?)',
               ('system', 'Application started successfully', ''))
    db.execute('INSERT INTO logs (log_type, message, flag_hint) VALUES (?, ?, ?)',
               ('security', 'Login attempt from admin', FLAGS['info_disclosure']))
    db.execute('INSERT INTO logs (log_type, message, flag_hint) VALUES (?, ?, ?)',
               ('error', 'Database connection timeout', ''))

    db.commit()
    db.close()

# ==================== HELPER FUNCTIONS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return 'Access denied', 403
        return f(*args, **kwargs)
    return decorated_function

def render_with_flag(template, **kwargs):
    """Render template, passing pending flag popup and found flags sidebar."""
    pending_flag = pop_pending_flag()
    found_flags = get_found_flags()
    return render_template(template,
                           pending_flag=pending_flag,
                           found_flags=found_flags,
                           **kwargs)

# ==================== MAIN ROUTES ====================

@app.route('/')
def index():
    return render_with_flag('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        # VULN: SQL Injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.md5(password.encode()).hexdigest()}'"

        try:
            cursor = db.execute(query)
            user = cursor.fetchone()

            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                # Clear per-user data on new login
                session['found_flags'] = session.get('found_flags', {})

                db.execute('UPDATE users SET session_id = ? WHERE id = ?',
                           (request.cookies.get('session', ''), user['id']))
                db.commit()

                # Award SQL injection flag if payload used
                if "'" in username or 'OR' in username.upper() or '--' in username:
                    set_pending_flag('sql_injection')

                # Award default creds flag
                if username == 'admin' and password == 'password123':
                    award_flag('broken_auth')

                response = make_response(redirect(url_for('dashboard')))
                if "'" in username or 'OR' in username.upper():
                    response.headers['X-Flag'] = FLAGS['sql_injection']
                return response
            else:
                return render_with_flag('login.html', error='Invalid credentials')
        except Exception as e:
            return render_with_flag('login.html', error=f'Database error: {str(e)}')

    return render_with_flag('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        # VULN: Role from hidden field
        role = request.form.get('role', 'student')

        db = get_db()
        password_hash = hashlib.md5(password.encode()).hexdigest()

        try:
            db.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                       (username, password_hash, email, role))
            db.commit()

            if role == 'admin':
                award_flag('privilege_escalation')
                return render_with_flag('register.html',
                                        success=True,
                                        flag=FLAGS['privilege_escalation'])

            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_with_flag('register.html', error='Username already exists')

    return render_with_flag('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user_id = session.get('user_id')

    enrollments = db.execute('''
        SELECT e.*, c.name, c.description, c.instructor
        FROM enrollments e
        JOIN courses c ON e.course_id = c.id
        WHERE e.user_id = ?
    ''', (user_id,)).fetchall()

    return render_with_flag('dashboard.html', enrollments=enrollments)

@app.route('/logout')
def logout():
    # VULN: Incomplete logout - doesn't clear all session data
    session.pop('user_id', None)
    return redirect(url_for('index'))

# ==================== API: Found Flags ====================

@app.route('/api/my-flags')
def api_my_flags():
    """Return this user's found flags as JSON for the sidebar."""
    found = get_found_flags()
    flags_list = [{'key': k, 'label': v['label'], 'value': v['value'], 'time': v['time']}
                  for k, v in found.items()]
    return jsonify({'count': len(flags_list), 'flags': flags_list})

# ==================== SEARCH ====================

@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []

    # Award XSS reflected flag if payload detected
    xss_flag = None
    if query and ('<script' in query.lower() or 'onerror' in query.lower() or 'javascript:' in query.lower()):
        award_flag('xss_reflected')
        xss_flag = FLAGS['xss_reflected']

    if query:
        db = get_db()
        results = db.execute(
            'SELECT * FROM courses WHERE name LIKE ? OR description LIKE ?',
            (f'%{query}%', f'%{query}%')
        ).fetchall()

    pending_flag = pop_pending_flag()
    found_flags = get_found_flags()
    return render_template('search.html',
                           query=query,
                           results=results,
                           xss_flag=xss_flag,
                           pending_flag=pending_flag,
                           found_flags=found_flags)

# ==================== COURSES ====================

@app.route('/courses')
def courses():
    db = get_db()
    all_courses = db.execute('SELECT * FROM courses').fetchall()
    return render_with_flag('courses.html', courses=all_courses)

@app.route('/course/<int:course_id>')
def course_detail(course_id):
    db = get_db()
    course = db.execute('SELECT * FROM courses WHERE id = ?', (course_id,)).fetchone()

    if not course:
        abort(404)

    # Per-user reviews only
    reviews = get_user_reviews(course_id)

    # Check if there's a stored XSS flag pending from a just-submitted review
    xss_stored_flag = session.pop('xss_stored_flag', None)
    session.modified = True

    pending_flag = pop_pending_flag()
    found_flags = get_found_flags()

    return render_template('course_detail.html',
                           course=course,
                           reviews=reviews,
                           xss_stored_flag=xss_stored_flag,
                           pending_flag=pending_flag,
                           found_flags=found_flags)

@app.route('/course/<int:course_id>/review', methods=['POST'])
@login_required
def submit_review(course_id):
    rating = request.form.get('rating', 5)
    comment = request.form.get('comment', '')
    user_id = session.get('user_id')

    # Store review per-user (session-isolated)
    add_user_review(course_id, rating, comment)

    # Detect stored XSS payload - award flag and queue popup after redirect
    if '<script' in comment.lower() or 'onerror' in comment.lower() or 'onload' in comment.lower():
        award_flag('xss_stored')
        # Store flag to show AFTER the injected alert() fires
        session['xss_stored_flag'] = FLAGS['xss_stored']
        session.modified = True

    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/enroll/<int:course_id>', methods=['POST'])
@login_required
def enroll_course(course_id):
    user_id = session.get('user_id')
    price = float(request.form.get('price', 0))
    discount = float(request.form.get('discount', 0))
    final_price = price - (price * discount / 100)

    db = get_db()
    db.execute('INSERT INTO enrollments (user_id, course_id) VALUES (?, ?)', (user_id, course_id))
    db.execute('INSERT INTO invoices (user_id, course_id, amount) VALUES (?, ?, ?)',
               (user_id, course_id, final_price))
    db.commit()

    if discount > 90:
        award_flag('csrf')
        return jsonify({'success': True, 'message': 'Enrollment successful!', 'flag': FLAGS['csrf']})

    return redirect(url_for('dashboard'))

# ==================== INVOICE / IDOR ====================

@app.route('/invoice/<int:invoice_id>')
@login_required
def view_invoice(invoice_id):
    db = get_db()

    # VULN: No ownership check - IDOR
    invoice = db.execute('''
        SELECT i.*, c.name as course_name, u.username
        FROM invoices i
        JOIN courses c ON i.course_id = c.id
        JOIN users u ON i.user_id = u.id
        WHERE i.id = ?
    ''', (invoice_id,)).fetchone()

    if not invoice:
        abort(404)

    # Award IDOR flag if accessing invoice not belonging to current user
    idor_flag = None
    if invoice['user_id'] != session.get('user_id'):
        award_flag('idor')
        idor_flag = FLAGS['idor']

    # Also award if accessing invoice #1 (admin's)
    if invoice_id == 1 and session.get('user_id') != 1:
        award_flag('idor')
        idor_flag = FLAGS['idor']

    return render_with_flag('invoice.html', invoice=invoice, idor_flag=idor_flag)

# ==================== FILE OPERATIONS ====================

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_with_flag('upload.html', error='No file selected')

        file = request.files['file']
        if file.filename == '':
            return render_with_flag('upload.html', error='No file selected')

        filename = file.filename
        filepath = os.path.join('uploads', filename)
        file.save(filepath)

        # VULN: No extension validation
        if filename.endswith(('.php', '.phtml', '.py', '.sh')):
            award_flag('file_upload')
            return render_with_flag('upload.html', success=True, flag=FLAGS['file_upload'])

        return render_with_flag('upload.html', success=True)

    return render_with_flag('upload.html')

@app.route('/download')
def download_file():
    filename = request.args.get('file', '')

    lfi_flag = None
    try:
        filepath = os.path.join('uploads', filename)

        if '../' in filename or 'etc/passwd' in filename or '.env' in filename:
            award_flag('path_traversal')
            lfi_flag = FLAGS['path_traversal']
            response = make_response(send_file(filepath))
            response.headers['X-LFI-Flag'] = FLAGS['lfi']
            return response

        return send_file(filepath)
    except Exception as e:
        return f'Error: {str(e)} — FLAG: {FLAGS["path_traversal"]}' if '../' in filename else f'Error: {str(e)}', 404

@app.route('/view')
def view_file():
    filename = request.args.get('file', '')

    try:
        with open(filename, 'r') as f:
            content = f.read()

        if 'flag' in filename.lower() or '../' in filename:
            award_flag('lfi')
            return Response(
                content + f'\n\n<!-- FLAG: {FLAGS["lfi"]} -->',
                mimetype='text/plain'
            )

        return Response(content, mimetype='text/plain')
    except Exception as e:
        return f'Error reading file: {str(e)}', 404

# ==================== COMMAND INJECTION ====================

@app.route('/ping', methods=['GET', 'POST'])
@login_required
def ping_tool():
    if request.method == 'POST':
        host = request.form.get('host', '')

        try:
            command = f'ping -c 4 {host}'
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10)
            output = result.decode('utf-8')

            cmdi_flag = None
            if ';' in host or '|' in host or '&&' in host or '`' in host:
                award_flag('command_injection')
                cmdi_flag = FLAGS['command_injection']

            return render_with_flag('ping.html', output=output, flag=cmdi_flag)
        except Exception as e:
            return render_with_flag('ping.html', output=f'Error: {str(e)}')

    return render_with_flag('ping.html')

# ==================== API ENDPOINTS ====================

@app.route('/api/users')
def api_users():
    db = get_db()
    users = db.execute('SELECT id, username, email, role, password FROM users').fetchall()

    users_list = []
    for user in users:
        users_list.append({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'password_hash': user['password'],
            'flag': FLAGS['api_exposure'] if user['role'] == 'admin' else ''
        })

    # Award flag for this user
    award_flag('api_exposure')
    award_flag('weak_hash')

    response = jsonify(users_list)
    # VULN: CORS misconfiguration
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['X-CORS-Flag'] = FLAGS['cors_misconfiguration']
    return response

@app.route('/api/course/<int:course_id>')
def api_course(course_id):
    db = get_db()
    course = db.execute('SELECT * FROM courses WHERE id = ?', (course_id,)).fetchone()
    if course:
        return jsonify(dict(course))
    return jsonify({'error': 'Course not found'}), 404

# ==================== JWT VULNERABILITIES ====================

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    db = get_db()
    password_hash = hashlib.md5(password.encode()).hexdigest()
    user = db.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                      (username, password_hash)).fetchone()

    if user:
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return jsonify({'token': token, 'message': 'Login successful'})

    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin/secret')
def api_admin_secret():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if not token:
        return jsonify({'error': 'No token provided'}), 401

    try:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM, 'none'])
        except:
            payload = jwt.decode(token, options={"verify_signature": False})

        if payload.get('role') == 'admin':
            award_flag('jwt_none')
            award_flag('jwt_weak')
            return jsonify({
                'secret': 'Admin secret data',
                'flag': FLAGS['jwt_none'],
                'weak_secret_flag': FLAGS['jwt_weak']
            })
        else:
            return jsonify({'error': 'Admin access required'}), 403

    except Exception as e:
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401

# ==================== XXE ====================

@app.route('/xml/upload', methods=['GET', 'POST'])
@login_required
def xml_upload():
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')

        try:
            parser = ET.XMLParser()
            tree = ET.fromstring(xml_data.encode(), parser=parser)

            result = {
                'tag': tree.tag,
                'text': tree.text,
                'children': [child.tag for child in tree]
            }

            if '<!ENTITY' in xml_data or 'SYSTEM' in xml_data:
                award_flag('xxe')
                result['flag'] = FLAGS['xxe']

            return render_with_flag('xml_upload.html', result=result)

        except Exception as e:
            return render_with_flag('xml_upload.html', error=f'XML parsing error: {str(e)}')

    return render_with_flag('xml_upload.html')

# ==================== SSTI ====================

@app.route('/template/render', methods=['GET', 'POST'])
@login_required
def template_render():
    if request.method == 'POST':
        template_string = request.form.get('template', '')
        name = request.form.get('name', 'User')

        try:
            from jinja2 import Template
            template = Template(template_string)
            output = template.render(name=name, flag=FLAGS['ssti'])

            ssti_flag = None
            if '{{' in template_string and '}}' in template_string:
                award_flag('ssti')
                ssti_flag = FLAGS['ssti']

            return render_with_flag('template_render.html',
                                    output=output,
                                    ssti_detected=bool(ssti_flag),
                                    flag=ssti_flag)

        except Exception as e:
            return render_with_flag('template_render.html', error=f'Template error: {str(e)}')

    return render_with_flag('template_render.html')

# ==================== DESERIALIZATION ====================

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    data = request.form.get('data', '')

    try:
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        award_flag('insecure_deserialization')
        return jsonify({'result': str(obj), 'flag': FLAGS['insecure_deserialization']})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ==================== OPEN REDIRECT ====================

@app.route('/redirect')
def open_redirect():
    url = request.args.get('url', '/')

    if url.startswith('http') and 'icss.edu' not in url:
        award_flag('open_redirect')
        response = make_response(redirect(url))
        response.headers['X-Redirect-Flag'] = FLAGS['open_redirect']
        return response

    return redirect(url)

# ==================== BLIND SQLi ====================

@app.route('/check_username')
def check_username():
    username = request.args.get('username', '')
    db = get_db()

    try:
        query = f"SELECT * FROM users WHERE username = '{username}'"
        start_time = time.time()
        cursor = db.execute(query)
        result = cursor.fetchone()
        elapsed_time = time.time() - start_time

        if elapsed_time > 2:
            award_flag('blind_sqli')
            return jsonify({'available': False, 'message': 'Username check completed', 'flag': FLAGS['blind_sqli']})

        # Also award on obvious SQL injection in username
        if "'" in username or 'SLEEP' in username.upper() or 'OR' in username.upper():
            award_flag('blind_sqli')
            return jsonify({'available': False, 'flag': FLAGS['blind_sqli'], 'message': 'SQL injection detected'})

        return jsonify({'available': result is None, 'message': 'Available' if result is None else 'Taken'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ==================== PASSWORD RESET ====================

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user:
            timestamp = str(int(time.time()))
            token = hashlib.md5(f"{user['id']}{timestamp}".encode()).hexdigest()
            db.execute('UPDATE users SET reset_token = ? WHERE id = ?', (token, user['id']))
            db.commit()

            return render_with_flag('reset_password.html',
                                    token_generated=True,
                                    token=token,
                                    user_id=user['id'])

        return render_with_flag('reset_password.html', error='Email not found')

    token = request.args.get('token')
    if token:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE reset_token = ?', (token,)).fetchone()

        if user:
            award_flag('broken_auth')
            return render_with_flag('reset_password.html',
                                    reset_form=True,
                                    token=token,
                                    flag=FLAGS['broken_auth'])

        return render_with_flag('reset_password.html', error='Invalid token')

    return render_with_flag('reset_password.html')

# ==================== ADMIN PANEL ====================

@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute('SELECT id, username, email, role, created_at FROM users').fetchall()
    courses = db.execute('SELECT * FROM courses').fetchall()
    enrollments = db.execute('SELECT COUNT(*) as count FROM enrollments').fetchone()

    award_flag('privilege_escalation')

    return render_with_flag('admin.html',
                            users=users,
                            courses=courses,
                            total_enrollments=enrollments['count'],
                            flag=FLAGS['privilege_escalation'])

# ==================== EXPOSED FILES ====================

@app.route('/robots.txt')
def robots():
    award_flag('robots_txt')
    content = f"""User-agent: *
Disallow: /admin
Disallow: /api/users
Disallow: /secret
Disallow: /backup
Disallow: /.git

# Secret administrative paths - Do not index
# Flag: {FLAGS['robots_txt']}"""
    return Response(content, mimetype='text/plain')

@app.route('/backup/')
@app.route('/backup')
def backup_dir():
    award_flag('directory_listing')
    award_flag('backup_file')
    return jsonify({'flag': FLAGS['backup_file'],
                    'directory_flag': FLAGS['directory_listing'],
                    'files': ['db_backup.sql', 'config.bak']})

@app.route('/backup/<path:filename>')
def backup_files(filename):
    award_flag('backup_file')
    try:
        return send_from_directory('backup', filename)
    except:
        return jsonify({'flag': FLAGS['backup_file'], 'files': ['db_backup.sql', 'config.bak']})

@app.route('/.env')
def env_file():
    award_flag('exposed_env')
    content = f"""# Environment Configuration
DATABASE_URL=sqlite:///icss_ctf.db
SECRET_KEY=super_secret_key_12345
JWT_SECRET=jwt_secret_123
ADMIN_PASSWORD=password123
API_KEY=sk-1234567890abcdef

# FLAG
FLAG={FLAGS['exposed_env']}

# AWS Credentials (dummy)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
    return Response(content, mimetype='text/plain')

@app.route('/logs/app.log')
def application_logs():
    award_flag('info_disclosure')
    db = get_db()
    logs = db.execute('SELECT * FROM logs ORDER BY created_at DESC LIMIT 50').fetchall()

    log_content = "=== ICSS Application Logs ===\n\n"
    for log in logs:
        log_content += f"[{log['created_at']}] {log['log_type'].upper()}: {log['message']}\n"
        if log['flag_hint']:
            log_content += f"FLAG: {log['flag_hint']}\n"

    return Response(log_content, mimetype='text/plain')

@app.route('/.git/')
@app.route('/.git/HEAD')
def git_exposure():
    award_flag('exposed_git')
    content = f"""ref: refs/heads/main
# FLAG: {FLAGS['exposed_git']}"""
    return Response(content, mimetype='text/plain')

# ==================== DEBUG ====================

@app.route('/debug/error')
def debug_error():
    award_flag('debug_mode')
    flag_variable = FLAGS['debug_mode']
    try:
        undefined_variable = this_will_cause_an_error  # noqa
    except Exception as e:
        return f"""<h1>Debug Error - Stack Trace</h1>
<pre>NameError: name 'this_will_cause_an_error' is not defined
  flag_variable = '{flag_variable}'
  
FLAG: {FLAGS['debug_mode']}
</pre>"""
    return "Unreachable"

@app.route('/phpinfo')
def phpinfo():
    import platform, sys
    award_flag('hardcoded_secret')
    info = {
        'Python Version': sys.version,
        'Platform': platform.platform(),
        'Flask Version': 'Flask 2.3.0',
        'Server': request.environ.get('SERVER_SOFTWARE', 'Unknown'),
        'Secret Key': app.secret_key,
        'JWT Secret': JWT_SECRET,
        'Database': DATABASE,
        'Debug Mode': str(app.debug),
        'Flag': FLAGS['hardcoded_secret']
    }
    html = "<h1>Server Information</h1><table border='1'>"
    for key, value in info.items():
        html += f"<tr><td><strong>{key}</strong></td><td>{value}</td></tr>"
    html += "</table>"
    return html

# ==================== CONTACT (CSRF) ====================

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        db = get_db()
        db.execute('INSERT INTO messages (name, email, subject, message) VALUES (?, ?, ?, ?)',
                   (name, email, subject, message))
        db.commit()

        referer = request.headers.get('Referer', '')
        if referer and 'icss' not in referer:
            award_flag('csrf')
            return jsonify({'success': True, 'message': 'Message sent successfully', 'flag': FLAGS['csrf']})

        return render_with_flag('contact.html', success=True)

    return render_with_flag('contact.html')

# ==================== JS CONFIG ====================

@app.route('/static/js/config.js')
def js_config():
    award_flag('js_source')
    js_content = f"""
// Application Configuration
const CONFIG = {{
    apiEndpoint: '/api',
    apiKey: 'api_key_1234567890',
    adminSecret: 'admin_secret_key',
    debugMode: true,
    // FLAG: {FLAGS['js_source']}
}};

// Development notes - Remove in production
// Admin credentials: admin/password123
// Database: SQLite (icss_ctf.db)
"""
    return Response(js_content, mimetype='application/javascript')

# ==================== OTHER PAGES ====================

@app.route('/about')
def about():
    return render_with_flag('about.html')

@app.route('/bruteforce-test', methods=['GET', 'POST'])
def bruteforce_test():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == 'secret_flag_password':
            award_flag('rate_limit')
            return jsonify({'success': True, 'flag': FLAGS['rate_limit']})
        return jsonify({'success': False, 'message': 'Wrong password'})
    return render_with_flag('bruteforce_test.html') if os.path.exists('templates/bruteforce_test.html') else jsonify({'message': 'POST to this endpoint with password field'})

@app.route('/session/set')
def set_session():
    session_id = request.args.get('session_id')
    if session_id:
        award_flag('session_fixation')
        response = make_response(redirect(url_for('index')))
        response.set_cookie('session', session_id)
        response.headers['X-Flag'] = FLAGS['session_fixation']
        return response
    return redirect(url_for('index'))

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return f"<h1>404 Not Found</h1><p>{request.path} was not found.</p>", 404

@app.errorhandler(500)
def server_error(e):
    return f"<h1>500 Internal Server Error</h1><pre>{str(e)}</pre>", 500

# ==================== INITIALIZATION ====================

def initialize_app():
    if not os.path.exists(DATABASE):
        init_db()

    os.makedirs('uploads', exist_ok=True)
    os.makedirs('backup', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)

    if not os.path.exists('uploads/flag.txt'):
        with open('uploads/flag.txt', 'w') as f:
            f.write(f"Congratulations! {FLAGS['lfi']}")

    if not os.path.exists('backup/config.bak'):
        with open('backup/config.bak', 'w') as f:
            f.write(f"DATABASE=icss_ctf.db\nADMIN_PASS=password123\nFLAG={FLAGS['backup_file']}")

    if not os.path.exists('backup/db_backup.sql'):
        with open('backup/db_backup.sql', 'w') as f:
            f.write(f"-- Database Backup\n-- FLAG: {FLAGS['backup_file']}\n")

if __name__ == '__main__':
    print("=" * 50)
    print("  ICSS India CTF - Starting Application v2.0")
    print("=" * 50)
    initialize_app()
    print("\n✅ Initialization complete!")
    print("🚀 Server running at: http://localhost:5000")
    print("\n⚠️  WARNING: This application is intentionally vulnerable!")
    print("   Each user gets their own isolated environment.")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False)
