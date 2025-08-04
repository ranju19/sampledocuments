app.py
from flask import Flask, request, jsonify, Response
from models import db, User
from config import Config

from flask import session, redirect, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from onelogin.saml2.settings import OneLogin_Saml2_Settings
import os



app = Flask(__name__)

threads = []

app.secret_key = 'gazI4ico4vdtzNgImdAecCci707oTRh1ihci0JDZ-LI'
app.config['SESSION_COOKIE_SECURE']=True
app.config['SESSION_COOKIE_SAMESITE']="None"
app.config['SESSION_COOKIE_HTTPONLY']= True
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/metadata/', methods=['GET', 'POST'])
def metadata_or_acs():
    if request.method == 'GET':
        # ... serve metadata XML ...
        pass
    else:  # POST
        #print("=== SAML POST received ===")
        #print("Form keys:", request.form.keys())
        #print("SAMLResponse:", request.form.get("SAMLResponse", "NO SAMLRESPONSE"))
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        auth.process_response()
        errors = auth.get_errors()
        print("SAML errors:", errors)
        if errors:
            return f"SAML error: {errors}"
        session['user'] = auth.get_nameid()
        session['samlUserdata'] = auth.get_attributes()
        print("SAML login successful. Session:", dict(session))
        return redirect(url_for('protected'))


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


@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/sls', methods=['GET', 'POST'])
def saml_sls():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    url = auth.process_slo()
    errors = auth.get_errors()
    if errors:
        return f"SAML SLS error: {errors}", 400

    return redirect('/')

@app.route('/protected')
def protected():
    print('Session:', dict(session))
    if 'user' not in session:
        print('Not logged in, redirecting to SAML login')
        return redirect(url_for('saml_login'))  # Or wherever your SSO login is
    return "Welcome! You are logged in as: " + session['user']

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

@app.route('/ping',methods=['GET'])
def ping():
    return "pong", 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
--------------
settings.json
{
  "strict": true,
  "debug": true,
  "sp": {
    "entityId": "https://technicalacumen.otsuka-us.com/metadata/",
    "assertionConsumerService": {
      "url": "https://technicalacumen.otsuka-us.com/metadata/",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    },
    "singleLogoutService": {
      "url": "https://technicalacumen.otsuka-us.com/saml/sls",
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
    "x509cert": "MIIC8DCCAdigAwIBAgIQfvqtosf0a4tP39yxfYusoTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNTA3MjkxNzU2MTFaFw0>
  }
}
-----------
nginx
server {
        listen 80;
        server_name technicalacumen.otsuka-us.com;
        return 301 https://$host$request_uri;
}


server{
  listen 443;
  server_name technicalacumen.otsuka-us.com;

  root /var/www/html;
  index index.html;

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}




--------------------------------------------------------------------------------------------------------------------------------------------------------
@app.route('/protected')
def protected():
    print('Session:', dict(session))
    if 'user' not in session:
        print('Not logged in, redirecting to SAML login')
        return redirect(url_for('saml_login'))  # Or wherever your SSO login is
    return "Welcome! You are logged in as: " + session['user']

-------------------
@app.route('/metadata/', methods=['GET', 'POST'])
def metadata_or_acs():
    if request.method == 'GET':
        # ... serve metadata XML ...
        pass
    else:  # POST
        print("=== SAML POST received ===")
        print("Form keys:", request.form.keys())
        print("SAMLResponse:", request.form.get("SAMLResponse", "NO SAMLRESPONSE"))
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        auth.process_response()
        errors = auth.get_errors()
        print("SAML errors:", errors)
        if errors:
            return f"SAML error: {errors}"
        session['samlUserdata'] = auth.get_attributes()
        return redirect(url_for('protected'))





---------------------------------------------------------------------------------------------
combined old
@app.route('/metadata/', methods=['GET', 'POST'])
def metadata_or_acs():
    if request.method == 'GET':
        # normal metadata
        saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path="saml")
        saml_metadata = OneLogin_Saml2_Metadata.builder(
            saml_settings.get_sp_data(), None, None
        )
        return Response(saml_metadata, mimetype='text/xml')
    else:  # POST
        # treat as ACS (authentication callback)
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            return f"SAML error: {errors}"
        session['samlUserdata'] = auth.get_attributes()
        return redirect(url_for('protected'))

--------------------------------------------------------------------
@app.route('/saml/sls', methods=['GET', 'POST'])
def saml_sls():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    url = auth.process_slo()
    errors = auth.get_errors()
    if errors:
        return f"SAML SLS error: {errors}", 400
    # After successful logout, redirect as needed (here, home page)
    return redirect('/')

--------------------------------------------------------------------
from flask import Flask, Response
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from onelogin.saml2.settings import OneLogin_Saml2_Settings

app = Flask(__name__)

@app.route('/metadata')
def metadata():
    saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path="saml")
    saml_metadata = OneLogin_Saml2_Metadata.builder(
        saml_settings.get_sp_data(),
        saml_settings.get_contact_person(),
        saml_settings.get_organization()
    )[0]
    return Response(saml_metadata, mimetype='text/xml')

------------------------------------------------
New settings.json
{
  "strict": true,
  "debug": true,
  "sp": {
    "entityId": "http://10.45.87.29:8000/metadata/",
    "assertionConsumerService": {
      "url": "http://10.45.87.29:8000/saml/acs/",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    },
    "singleLogoutService": {
      "url": "http://10.45.87.29:8000/saml/sls/",
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
    "x509cert": "MIIC8DCCAdigAwIBAgIQfvqtosf0a4tP39yxfYusoTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yNTA3MjkxNzU2MTFaFw0yODA3MjkxNzU2MTFaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueiSa6qmEWWbabDFoGj7eA1JulBGbKiRPbHtloSfGSqUvY8kLIehrVmtScD0Bc+/Pf5cWsYaOYQa4X37QvRETGlOOOpJHCmHwgAZRbs/jEMCk5Cxt279I3G27682XVojIstwbwTJjHObpZR79ez2LyFuHWvcXe42fRqKbCDclEW9mNdAM2DymZYSI6tlDpVUmIoiMKk7KB5/RpDoBEXhl2ksYW4GidqULFCri98IxAAlwrdO8n7HVbuqmXj7qPLT1qrbYDum440PrVL/+grSXJBo2rOYikdWgdx/ymfKhvrTXVM8JiW6Zm7Z0eYdadF37Y3KTxwU95fP21hbz2hF1QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA1puJa9iV0f57r3ILLcfqIoDY2NtT9R8m/VDyudyBSW3Eb99V9Z67Xy7Z2kX/7GLIA3y0Ykln57CzoWK7Dl49fhcSkSLmedy6pdoHzhEkZ5SLw1PQARQxUKwhJSoaCiwv5sk0A+WzvDsbGWHUB//Ljmjy4cvkayc2tpv0iCm1Aeq1A/hHIxVjtNBH3dMS4q3QjLfk+5bhzJbhuSAWm+ai6PXryiEzavDd8KcNVX9DZZAlgiWGvPMUWTSe5xE7Kl7ALn20MTVVJC9/yKu+sVKcqkXQIuA+nMaNyzbiXXnWomRm1XSy3USzGdOHnzOvOlW62erBd8ArKkfj44AaKQFFs"
  }
}



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

