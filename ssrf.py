
"""
Запуск: python3 vulnerable_app.py
Слушает 0.0.0.0:5000
"""
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

INTERNAL_SECRET = "FLAG{ssrf_internal_access}"

@app.route("/")
def index():
    return """
    <h1>Уязвимое приложение</h1>
    <p>Не открывай: <a href="https://www.youtube.com/watch?v=-yc3PenJCHk&amp;t=2751s">Жёсткое паки хой</a></p>
    """

@app.route("/fetch")
def fetch():
    """УЯЗВИМЫЙ эндпоинт: загружает URL без валидации."""
    url = request.args.get("url")
    if not url:
        return jsonify(error="Параметр url обязателен"), 400

    try:
        # ⚠️ УЯЗВИМОСТЬ: нет проверки на приватные IP и схемы
        response = requests.get(url, timeout=5)
        return jsonify(
            status=response.status_code,
            content=response.text[:2000]
        )
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route("/admin")
def admin():
    """Внутренний ресурс, который не должен быть доступен извне."""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify(error="Forbidden"), 403
    return jsonify(secret=INTERNAL_SECRET)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)