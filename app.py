from flask import Flask, render_template, request, jsonify
import random
import string

app = Flask(__name__)

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
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
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
