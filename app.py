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

