from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import random
import string
import hashlib
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Замените на случайный ключ в продакшене

# Файл для хранения пользователей
USERS_FILE = 'users.txt'

def hash_password(password):
    """Хеширование пароля"""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    """Загрузка пользователей из файла"""
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    username, password_hash = line.strip().split('|||')
                    users[username] = password_hash
    return users

def save_user(username, password_hash):
    """Сохранение пользователя в файл"""
    with open(USERS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{username}|||{password_hash}\n")

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

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = load_users()
        
        if username in users and users[username] == hash_password(password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Неверное имя пользователя или пароль')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        users = load_users()
        
        if not username or not password:
            return render_template('register.html', error='Заполните все поля')
        
        if password != confirm_password:
            return render_template('register.html', error='Пароли не совпадают')
        
        if username in users:
            return render_template('register.html', error='Пользователь уже существует')
        
        # Сохраняем нового пользователя
        password_hash = hash_password(password)
        save_user(username, password_hash)
        
        session['username'] = username
        return redirect(url_for('index'))
    
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
        
        return jsonify({
            'success': True,
            'password': password
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True)
