from utils import add_params_to_uri
import time
import string
import json
import logging
from jose import jwt
from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)


SECRET_KEY = "ABCD"
CLIENT_ID = "foo123"
CLIENT_SECRET = "bar123"

log = logging.getLogger(__name__)
app.logger.setLevel(logging.DEBUG)


# https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
# MOCK_DB = {
#     "1": {
#         "name": "Iron Man",
#         "email": "iron_man@founder.avenger",
#         "profile": "https://test-oidc.onrender.com/static/ironman.jpeg",
#     }
# }

# name = None
# email = None
# profile = None
# MOCK_DB = {
#     "1": { "name": name, "email": email}
# }

MOCK_DB = {}
def lookup_user(user_id):
    """
    TODO replace this with a call to the database
    """
    return MOCK_DB[user_id]



@app.route('/login/', methods=['GET', 'POST'])
def login():
    # global name
    # global email
    # global profile
    # global MOCK_DB
    if request.method == 'GET':
        return render_template('login.html',)
    else:
        
        email = request.form['email']
        # profile = request.form['profile']
        # MOCK_DB["1"] = { "name": name, "email": email }
        # print(MOCK_DB)
        # create a MOCK_DB entry for the user
       
        MOCK_DB["1"] = {"email": email,"family_name":"Kyle","locale":"es-SV"}
        print(MOCK_DB)
        return render_template('home.html',email=email)


@app.route("/logout")
def logout():
    MOCK_DB["1"] = {"name": None}
    return redirect(url_for('home'))




@app.route("/authorize")
def authorize():
    # TODO Look up the flask session to see who is logged in
    # Eg. session["profile"]["user_id"]
    authorization_code = jwt.encode({"user_id": 1}, SECRET_KEY, algorithm="HS256")
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
