from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import random
import string
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Конфигурация базы данных
DATABASE = 'users.db'

# Флаг для отслеживания инициализации БД
db_initialized = False

def init_db():
    """Инициализация базы данных"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Создание таблицы пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Создание таблицы для истории генерации паролей (опционально)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            generated_password TEXT,
            length INTEGER,
            use_uppercase BOOLEAN,
            use_numbers BOOLEAN,
            use_special BOOLEAN,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("База данных инициализирована")

def get_db_connection():
    """Получение соединения с базой данных"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Для доступа к колонкам по имени
    return conn

def load_users():
    """Загрузка пользователей из базы данных"""
    users = {}
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username, password FROM users')
        rows = cursor.fetchall()
        
        for row in rows:
            users[row['username']] = row['password']
        
        conn.close()
    except Exception as e:
        print(f"Ошибка при загрузке пользователей: {e}")
    
    return users

def save_user(username, password):
    """Сохранение пользователя в базу данных"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            (username, password)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print("Пользователь с таким именем уже существует")
        return False
    except Exception as e:
        print(f"Ошибка при сохранении пользователя: {e}")
        return False

def save_password_history(user_id, password, length, use_uppercase, use_numbers, use_special):
    """Сохранение истории генерации паролей"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO password_history 
               (user_id, generated_password, length, use_uppercase, use_numbers, use_special) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (user_id, password, length, use_uppercase, use_numbers, use_special)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Ошибка при сохранении истории: {e}")
        return False

def get_user_id(username):
    """Получение ID пользователя"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        conn.close()
        return row['id'] if row else None
    except Exception as e:
        print(f"Ошибка при получении ID пользователя: {e}")
        return None

def get_all_users_data():
    """Получение всех пользователей для отображения"""
    users = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, created_at FROM users ORDER BY created_at DESC')
        rows = cursor.fetchall()
        
        for row in rows:
            users.append({
                'id': row['id'],
                'username': row['username'],
                'created_at': row['created_at']
            })
        
        conn.close()
    except Exception as e:
        print(f"Ошибка при получении данных пользователей: {e}")
    
    return users

def generate_password(length=12, use_uppercase=True, use_numbers=True, use_special=True):
    characters = string.ascii_lowercase
    
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not characters:
        characters = string.ascii_lowercase
    
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

@app.before_request
def initialize_database():
    """Инициализация базы данных перед первым запросом"""
    global db_initialized
    if not db_initialized:
        init_db()
        db_initialized = True

@app.route('/')
def index():
    if 'username' in session:
        all_users = get_all_users_data()
        return render_template('index.html', 
                             username=session['username'],
                             all_users=all_users)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return render_template('login.html', error='Заполните все поля')
        
        users = load_users()
        
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Неверное имя пользователя или пароль')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        users = load_users()
        
        if not username or not password:
            return render_template('register.html', error='Заполните все поля')
        
        if len(username) < 3:
            return render_template('register.html', error='Имя пользователя должно быть не менее 3 символов')
        
        if len(password) < 4:
            return render_template('register.html', error='Пароль должен быть не менее 4 символов')
        
        if password != confirm_password:
            return render_template('register.html', error='Пароли не совпадают')
        
        if username in users:
            return render_template('register.html', error='Пользователь уже существует')
        
        if save_user(username, password):
            return redirect(url_for('login') + '?success=1')
        else:
            return render_template('register.html', error='Ошибка при сохранении пользователя')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/generate', methods=['POST'])
def generate():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Требуется авторизация'})
    
    try:
        data = request.get_json()
        length = int(data.get('length', 12))
        use_uppercase = data.get('uppercase', True)
        use_numbers = data.get('numbers', True)
        use_special = data.get('special', True)

        if length < 1:
            length = 1
        elif length > 50:
            length = 50
            
        password = generate_password(length, use_uppercase, use_numbers, use_special)
        
        # Сохраняем историю генерации
        user_id = get_user_id(session['username'])
        if user_id:
            save_password_history(user_id, password, length, use_uppercase, use_numbers, use_special)
        
        return jsonify({
            'success': True,
            'password': password
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Произошла ошибка'
        })

@app.route('/view_database')
def view_database():
    """Просмотр содержимого базы данных"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Требуется авторизация'})
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Получаем данные пользователей
        cursor.execute('SELECT * FROM users')
        users_data = cursor.fetchall()
        users = [dict(row) for row in users_data]
        
        # Получаем историю генерации паролей
        cursor.execute('''
            SELECT ph.*, u.username 
            FROM password_history ph 
            JOIN users u ON ph.user_id = u.id 
            ORDER BY ph.created_at DESC
        ''')
        history_data = cursor.fetchall()
        history = [dict(row) for row in history_data]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'users': users,
            'password_history': history
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Ошибка при чтении базы данных: {e}'
        })

@app.route('/user_history')
def user_history():
    """Просмотр истории генерации паролей текущего пользователя"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Требуется авторизация'})
    
    try:
        user_id = get_user_id(session['username'])
        if not user_id:
            return jsonify({'success': False, 'error': 'Пользователь не найден'})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT generated_password, length, use_uppercase, use_numbers, use_special, created_at
            FROM password_history 
            WHERE user_id = ? 
            ORDER BY created_at DESC
            LIMIT 50
        ''', (user_id,))
        
        history_data = cursor.fetchall()
        history = [dict(row) for row in history_data]
        conn.close()
        
        return jsonify({
            'success': True,
            'history': history
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Ошибка при получении истории: {e}'
        })

# Альтернативный способ инициализации - при запуске приложения
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True)
