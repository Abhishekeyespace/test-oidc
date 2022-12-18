from utils import add_params_to_uri
import time
import logging
from jose import jwt
from flask import Flask, redirect, render_template, request, session, url_for
import uuid

app = Flask(__name__)

app.secret_key = 'BAD_SECRET_KEY'
SECRET_KEY = "ABCD"
CLIENT_ID = "foo123"
CLIENT_SECRET = "bar123"

log = logging.getLogger(__name__)
app.logger.setLevel(logging.DEBUG)

MOCK_DB = {}

def lookup_user(user_id):
    return MOCK_DB[user_id]

# @app.route('/login/', methods=['GET', 'POST'])
# def login():
#     if request.method == 'GET':
#         return render_template('login.html',)
#     else:
#         family_name = request.form['family_name']
#         given_name = request.form['given_name']
#         email = request.form['email']
#         user_id = str(uuid.uuid4())
#         session['user_id'] = user_id
#         MOCK_DB[user_id] = {'family_name': family_name, 'given_name': given_name, 'email': email}
#         return render_template('home.html',email=email)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        family_name = request.form['family_name']
        given_name = request.form['given_name']
        email = request.form['email']
        user_id = str(uuid.uuid4())
        # check if user does not exist, then create new user
        if user_id not in MOCK_DB:
            MOCK_DB[user_id] = {'family_name': family_name, 'given_name': given_name, 'email': email}
        session['user_id'] = user_id
        return render_template('home.html',email=email)



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/authorize")
def authorize():
    user_id = session['user_id']
    authorization_code = jwt.encode({"user_id": user_id}, SECRET_KEY, algorithm="HS256")
    params = [("code", authorization_code), ("state", request.args.get("state"))]
    uri = add_params_to_uri(request.args.get("redirect_uri"), params)
    return "", 302, [("Location", uri)]

@app.route("/token", methods=["POST"])
def token():
    if request.form["client_secret"] != CLIENT_SECRET:
        return "Incorrect client secret", 403
    now = int(time.time())
    user = jwt.decode(request.form["code"], SECRET_KEY, algorithms=["HS256"])
    user_id = str(user["user_id"])
    user_info = lookup_user(user_id)
    print(user_info)
    id_payload = {
        "iss": "https://test-oidc.onrender.com",
        "aud": CLIENT_ID,
        "sub": 'eyespace-123',
        "iat": now,
        "exp": now + 3600,
    }
    id_payload.update(user_info)
    token = {
        "access_token": "abc",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": jwt.encode(id_payload, SECRET_KEY, algorithm="HS256"),
    }
    default_json_headers = [
        ("Content-Type", "application/json"),
        ("Cache-Control", "no-store"),
        ("Pragma", "no-cache"),
    ]
    return token, 200, default_json_headers

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/healthz")
def healthz():
    return "OK"

if __name__ == "__main__":
    app.run(host="localhost", port=8080, debug=True)
