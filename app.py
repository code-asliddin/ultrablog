from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'ultra-secret-key-2024'

# === DATABASE ===
def get_db():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT DEFAULT "Umumiy",
            image_url TEXT DEFAULT "",
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            views INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT DEFAULT "",
            role TEXT DEFAULT "user",
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    admin = conn.execute('SELECT * FROM admin').fetchone()
    if not admin:
        conn.execute('INSERT INTO admin (username, password) VALUES (?, ?)',
            ('admin', generate_password_hash('admin123')))
    conn.commit()
    conn.close()

# === HELPERS ===
def get_gravatar(email, size=80):
    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d=identicon"

def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append("Kamida 8 ta belgi")
    if not re.search(r'[A-Z]', password):
        errors.append("Kamida 1 ta katta harf")
    if not re.search(r'[0-9]', password):
        errors.append("Kamida 1 ta raqam")
    return errors

def current_user():
    if session.get('user_id'):
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
        conn.close()
        return user
    return None

# === MAIN ROUTES ===
@app.route('/')
def index():
    conn = get_db()
    category = request.args.get('cat', '')
    search = request.args.get('q', '')
    if search:
        posts = conn.execute('SELECT * FROM posts WHERE title LIKE ? OR content LIKE ? ORDER BY created_at DESC',
            (f'%{search}%', f'%{search}%')).fetchall()
    elif category:
        posts = conn.execute('SELECT * FROM posts WHERE category=? ORDER BY created_at DESC', (category,)).fetchall()
    else:
        posts = conn.execute('SELECT * FROM posts ORDER BY created_at DESC').fetchall()
    categories = conn.execute('SELECT DISTINCT category FROM posts').fetchall()
    popular = conn.execute('SELECT * FROM posts ORDER BY views DESC LIMIT 5').fetchall()
    conn.close()
    return render_template('index.html', posts=posts, categories=categories,
                           popular=popular, search=search, user=current_user())

@app.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    conn = get_db()
    conn.execute('UPDATE posts SET views = views + 1 WHERE id=?', (id,))
    conn.commit()
    p = conn.execute('SELECT * FROM posts WHERE id=?', (id,)).fetchone()
    related = conn.execute('SELECT * FROM posts WHERE category=? AND id!=? LIMIT 3', (p['category'], id)).fetchall()

    if request.method == 'POST':
        if not session.get('user_id'):
            flash('Izoh yozish uchun tizimga kiring!')
            return redirect(url_for('login'))
        content = request.form['content'].strip()
        if content:
            conn.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?,?,?)',
                (id, session['user_id'], content))
            conn.commit()
            flash('Izoh qo\'shildi!')

    comments = conn.execute('''
        SELECT comments.*, users.username, users.email
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ?
        ORDER BY comments.created_at DESC
    ''', (id,)).fetchall()
    conn.close()
    return render_template('post.html', post=p, related=related,
                           comments=comments, user=current_user(), get_gravatar=get_gravatar)

# === AUTH ROUTES ===
@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm']

        # Validatsiya
        errors = []
        if len(username) < 3:
            errors.append("Username kamida 3 ta belgi bo'lishi kerak")
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username faqat harf, raqam va _ dan iborat bo'lsin")
        if not re.match(r'^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$', email):
            errors.append("Email noto'g'ri formatda")
        if password != confirm:
            errors.append("Parollar mos kelmadi")
        errors += validate_password(password)

        if errors:
            for e in errors:
                flash(e)
            return render_template('auth/register.html', user=None)

        conn = get_db()
        existing = conn.execute('SELECT id FROM users WHERE username=? OR email=?', (username, email)).fetchone()
        if existing:
            flash('Bu username yoki email allaqachon ro\'yxatdan o\'tgan!')
            conn.close()
            return render_template('auth/register.html', user=None)

        conn.execute('INSERT INTO users (username, email, password) VALUES (?,?,?)',
            (username, email, generate_password_hash(password)))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        conn.close()
        session['user_id'] = user['id']
        session['username'] = user['username']
        flash(f'Xush kelibsiz, {username}! 🎉')
        return redirect(url_for('index'))

    return render_template('auth/register.html', user=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        login_input = request.form['login'].strip()
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=? OR email=?',
            (login_input, login_input)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            if not user['is_active']:
                flash('Hisobingiz bloklangan!')
                return render_template('auth/login.html', user=None)
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Xush kelibsiz, {user["username"]}! 👋')
            return redirect(url_for('index'))
        flash('Login yoki parol xato!')
    return render_template('auth/login.html', user=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/profile/<username>')
def profile(username):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not user:
        return "Foydalanuvchi topilmadi", 404
    comments_count = conn.execute('SELECT COUNT(*) FROM comments WHERE user_id=?', (user['id'],)).fetchone()[0]
    conn.close()
    return render_template('auth/profile.html', profile_user=user,
                           comments_count=comments_count, user=current_user(),
                           get_gravatar=get_gravatar)

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    if request.method == 'POST':
        bio = request.form['bio'].strip()
        conn.execute('UPDATE users SET bio=? WHERE id=?', (bio, session['user_id']))
        conn.commit()
        flash('Profil yangilandi!')
        return redirect(url_for('profile', username=user['username']))
    conn.close()
    return render_template('auth/edit_profile.html', user=user, get_gravatar=get_gravatar)

# === ADMIN ROUTES ===
@app.route('/admin', methods=['GET','POST'])
def admin_login():
    if session.get('admin'):
        return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        conn = get_db()
        a = conn.execute('SELECT * FROM admin').fetchone()
        if a['username'] == request.form['username'] and check_password_hash(a['password'], request.form['password']):
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        flash('Xato login yoki parol!')
    return render_template('admin/login.html', user=None)

@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    posts = conn.execute('SELECT * FROM posts ORDER BY created_at DESC').fetchall()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('admin/panel.html', posts=posts, users=users, user=None)

@app.route('/admin/new', methods=['GET','POST'])
def new_post():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    if request.method == 'POST':
        conn = get_db()
        conn.execute('INSERT INTO posts (title, content, category, image_url) VALUES (?,?,?,?)',
            (request.form['title'], request.form['content'],
             request.form['category'], request.form['image_url']))
        conn.commit()
        conn.close()
        flash('Post muvaffaqiyatli qo\'shildi!')
        return redirect(url_for('admin_panel'))
    return render_template('admin/new_post.html', user=None)

@app.route('/admin/delete/<int:id>')
def delete_post(id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    conn.execute('DELETE FROM posts WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/block/<int:id>')
def block_user(id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (id,)).fetchone()
    new_status = 0 if user['is_active'] else 1
    conn.execute('UPDATE users SET is_active=? WHERE id=?', (new_status, id))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':

    app.run(debug=True, host='0.0.0.0', port=5000)
