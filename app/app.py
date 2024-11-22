from flask import session, Flask, jsonify, request, Response, render_template, render_template_string, url_for
from flask_sqlalchemy import SQLAlchemy
import jwt
from jwt.exceptions import DecodeError, MissingRequiredClaimError, InvalidKeyError
import json
import hashlib
import datetime
import os
from faker import Faker
import secrets
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from docx import Document
import yaml

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

# Use environment variables for sensitive data
app_port = os.environ.get('APP_PORT', 5050)

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY_HMAC'] = os.environ.get('SECRET_KEY_HMAC', 'default_secret_key')
app.config['SECRET_KEY_HMAC_2'] = os.environ.get('SECRET_KEY_HMAC_2', 'default_secret_key_2')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_flask_secret')
app.config['STATIC_FOLDER'] = None

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80), unique=True)

    def __repr__(self):
        return "<User {0}>".format(self.username)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    email = db.Column(db.String(80))
    ccn = db.Column(db.String(80), nullable=True)
    username = db.Column(db.String(80))
    password = db.Column(db.String(150))

    def __repr__(self):
        return "<User {0} {1}>".format(self.first_name, self.last_name)

@app.before_first_request
def setup_users():
    db.create_all()

    if not User.query.first():
        user = User()
        user.username = 'admin'
        # Replace hardcoded password with hashed password
        user.password = generate_password_hash('admin123')
        db.session.add(user)
        db.session.commit()

    if not Customer.query.first():
        for i in range(0, 5):
            fake = Faker()
            cust = Customer()
            cust.first_name = fake.first_name()
            cust.last_name = fake.last_name()
            cust.email = fake.simple_profile(sex=None)['mail']
            cust.username = fake.simple_profile(sex=None)['username']
            # Use base64 encoding for passwords if needed
            cust.password = str(base64.b64encode(secrets.token_bytes(16)))
            cust.ccn = fake.credit_card_number(card_type=None)
            db.session.add(cust)
            db.session.commit()

def get_exp_date():
    exp_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=240)
    return exp_date

def verify_jwt(token):
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY_HMAC'], algorithms=['HS256'])
        print("JWT Token from API: {0}".format(decoded))
        return True
    except DecodeError:
        print("Error in decoding token")
        return False
    except MissingRequiredClaimError as e:
        print('Claim required is missing: {0}'.format(e))
        return False

@app.route('/register/user', methods=['POST'])
def reg_customer():
    try:
        content = request.json
        if content:
            username = content['username']
            password = content['password']
            # Use secure password hashing
            hash_pass = generate_password_hash(password)
            new_user = User(username=username, password=hash_pass)
            db.session.add(new_user)
            db.session.commit()
            user_created = 'User: {0} has been created'.format(username)
            return jsonify({'Created': user_created}), 200
    except Exception as e:
        return jsonify({'Error': str(e)}), 404

@app.route('/search', methods=['POST'])
def search_customer():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'Error': 'Not Authenticated!'}), 403
    else:
        if not verify_jwt(token):
            return jsonify({'Error': 'Invalid Token'}), 403
        else:
            content = request.json
            results = []
            if content:
                try:
                    search_term = content['search']
                    print(search_term)
                    # Use parameterized queries
                    search_query = db.engine.execute(
                        "SELECT first_name, last_name, username FROM customer WHERE username = :username",
                        {"username": search_term}
                    )
                    for result in search_query:
                        results.append(list(result))
                    print(results)
                    return jsonify(results), 200
                except Exception as e:
                    return jsonify({'Error': str(e)}), 404

@app.route("/yaml_hammer", methods=['POST'])
def yaml_hammer():
    if request.method == "POST":
        f = request.files['file']
        rand = secrets.randbelow(100)
        fname = secure_filename(f.filename)
        fname = str(rand) + fname  # change file name
        cwd = os.getcwd()
        file_path = cwd + '/Files/' + fname
        f.save(file_path)  # save file locally

        with open(file_path, 'r') as yfile:
            y = yfile.read()

        # Use safe_load for YAML
        ydata = yaml.safe_load(y)

    return jsonify(name=json.dumps(ydata))

if __name__ == "__main__":
    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(app_port)
    IOLoop.instance().start()
