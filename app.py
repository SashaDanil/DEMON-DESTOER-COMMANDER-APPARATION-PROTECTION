from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import random
import string
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

USERS_FILE = 'users.txt'

def load_users():
    """Загрузка пользователей из файла"""
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and '|||' in line:
                        username, password = line.split('|||', 1)
                        users[username] = password
        except Exception as e:
            print(f"Ошибка при загрузке пользователей: {e}")
    return users

def save_user(username, password):
    """Сохранение пользователя в файл"""
    try:
        with open(USERS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{username}|||{password}\n")
        return True
    except Exception as e:
        print(f"Ошибка при сохранении: {e}")
        return False

def get_file_content():
    """Получение полного содержимого файла"""
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return f.read()
        return "Файл не существует"
    except Exception as e:
        return f"Ошибка при чтении файла: {e}"

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
        all_users = load_users()
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
        
        return jsonify({
            'success': True,
            'password': password
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Произошла ошибка'
        })

@app.route('/view_file')
def view_file():
    """Просмотр содержимого файла users.txt"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Требуется авторизация'})
    
    file_content = get_file_content()
    return jsonify({
        'success': True,
        'content': file_content
    })

if __name__ == '__main__':
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            f.write("# Файл пользователей\n")
    app.run(debug=True)
