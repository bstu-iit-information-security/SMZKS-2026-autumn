from flask import Flask, request

app = Flask(__name__)

# (/api/login, /search, /api/register, /api/password_reset, /api/profile)
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    # Уязвимый параметр для проверки SQLi из Задания 1
    # WAF должен заблокировать запрос до того, как он дойдет сюда
    user_id = request.args.get('id', '')

    return f"Backend OK. Endpoint reached: /{path}", 200


if __name__ == '__main__':
    # Запускаем на 5000 порту
    app.run(host='0.0.0.0', port=5000)