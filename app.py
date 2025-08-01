


Settings.json
{
  "strict": true,
  "debug": true,
  "sp": {
    "entityId": "http://localhost:5000/metadata/",
    "assertionConsumerService": {
      "url": "http://localhost:5000/saml/acs/",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    },
    "singleLogoutService": {
      "url": "http://localhost:5000/saml/sls/",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "",
    "privateKey": ""
  },
  "idp": {
    "entityId": "https://sts.windows.net/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/",
    "singleSignOnService": {
      "url": "https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/saml2",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "singleLogoutService": {
      "url": "https://login.microsoftonline.com/34ddb339-7fd0-4f00-9041-c2e47fbbc9f4/saml2",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "<X509Certificate>MIIC8DCCAdigAwIBAgIQfvqtosf0a4tP39yxfYusoTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNT>
  }
}








---------------------------------------------------------------------------------------------
sudo ln -s /etc/nginx/sites-available/flaskapp /etc/nginx/sites-enabled/

sudo rm /etc/nginx/sites-enabled/default


server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}



curl -X POST -H "Content-Type: application/json" -d '{"message":"Hello"}' http://127.0.0.1:8000/api/threads


@app.route('/api/threads', methods=['GET', 'POST'])
def threads_api():
    if request.method == 'GET':
        return jsonify(threads)
    elif request.method == 'POST':
        data = request.json
        # Simple validation (adjust as needed)
        if not data or 'message' not in data:
            return jsonify({"error": "No message provided"}), 400
        threads.append({"message": data['message']})
        return jsonify({"status": "ok"}), 201



@app.route('/api/threads', methods=['GET'])
def get_threads():
    # Sample threads. Replace this with your DB logic if needed.
    threads = [
        {"id": 1, "title": "Welcome!", "user": "admin"},
        {"id": 2, "title": "First Chatroom Thread", "user": "ranju"},
    ]
    return jsonify(threads), 200



1
Directly BELOW it, add:
from flask import session, redirect, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import os

2
def prepare_flask_request(request):
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ.get('SERVER_PORT'),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

def init_saml_auth(req):
    return OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.getcwd(), 'saml'))

3
@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        return f"SAML error: {errors}"
    session['samlUserdata'] = auth.get_attributes()
    return redirect(url_for('protected'))

@app.route('/protected')
def protected():
    if 'samlUserdata' in session:
        return jsonify({"SSO_user": session['samlUserdata']})
    return redirect(url_for('saml_login'))

4
app.secret_key = 'some-super-secret-key'  # use a strong, random value for production!






from flask import Flask, request, jsonify
from models import db, User
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({"error": "Missing fields"}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "User exists"}), 400
    user = User(username=data['username'], password=data['password'], email=data['email'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Signup successful!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username'], password=data['password']).first()
    if user:
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/search', methods=['GET'])
def search():
    q = request.args.get('q', '')
    results = User.query.filter(User.username.ilike(f'%{q}%')).all()
    return jsonify([{"username": u.username, "email": u.email} for u in results])

@app.route('/ping',methods=['GET'])
def ping():
    return "pong", 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)

