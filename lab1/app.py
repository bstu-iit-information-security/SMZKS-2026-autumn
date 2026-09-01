import sqlite3
from flask import Flask, request, render_template_string, jsonify, make_response
import jwt
import datetime

app = Flask(__name__)
JWT_SECRET = "student2026" # уязвимый слабый ключ для взлома

def init_db():
    conn = sqlite3.connect('lab.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, private_data TEXT)')
    c.execute('DELETE FROM users')
    c.execute("INSERT INTO users VALUES (1, 'admin', 'SuperSecretAdmin123!', 'admin', 'FLAG{admin_master_key}')")
    for i in range(2, 20):
        c.execute(f"INSERT INTO users VALUES ({i}, 'student{i}', 'pass{i}', 'user', 'FLAG{{secret_data_{i}}}')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return "<h3>Лабораторная работа №1. Web AppSec</h3><p>Эндпоинты: /login, /search, /api/profile/&lt;id&gt;, /admin</p>"

# уязвимость 1: SQL-инъекция
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    conn = sqlite3.connect('lab.db')
    c = conn.cursor()
    # уязвимый запрос без параметризации
    query = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{password}'"
    try:
        c.execute(query)
        user = c.fetchone()
        if user:
            token = jwt.encode({'user_id': user[0], 'username': user[1], 'role': user[2], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, JWT_SECRET, algorithm='HS256')
            resp = make_response(f"Login success. Role: {user[2]}")
            # уязвимые cookies: без HttpOnly, Secure и SameSite
            resp.set_cookie('auth_token', token)
            return resp
        return "Invalid credentials", 401
    except Exception as e:
        return str(e), 500

# уязвимость 2: Reflected XSS
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    # уязвимый рендеринг без санитизации
    template = f"<h1>Результаты поиска для: {query}</h1><p>Ничего не найдено.</p>"
    return render_template_string(template)


# уязвимость 3: BOLA / IDOR
@app.route('/api/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    # уязвимость: нет проверки, принадлежит ли запрашиваемый ID текущему авторизованному пользователю
    conn = sqlite3.connect('lab.db')
    c = conn.cursor()
    c.execute("SELECT username, private_data FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    if user:
        return jsonify({"username": user[0], "private_data": user[1]})
    return jsonify({"error": "User not found"}), 404

# уязвимость 4: ненадежный JWT
@app.route('/admin', methods=['GET'])
def admin_panel():
    token = request.cookies.get('auth_token')
    if not token:
        return "Unauthorized: No token", 401
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if decoded.get('role') == 'admin':
            return "<h1>Панель администратора</h1><p>Флаг захвачен: FLAG{JWT_FORGED_SUCCESS}</p>"
        return f"Access Denied. Current role: {decoded.get('role')}", 403
    except jwt.ExpiredSignatureError:
        return "Token expired", 401
    except jwt.InvalidTokenError:
        return "Invalid token", 401

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)