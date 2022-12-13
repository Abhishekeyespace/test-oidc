from utils import add_params_to_uri
import time
import string
import json
import logging
from jose import jwt
from flask import Flask, request

app = Flask(__name__)


SECRET_KEY = "ABCD"
CLIENT_ID = 'foo123'
CLIENT_SECRET = 'bar123'

log = logging.getLogger(__name__)
app.logger.setLevel(logging.DEBUG)


@app.route("/authorize")
def authorize():
    print("authorize endpoint: Printing request headers")
    print(request.headers)
    print("authorize endpoint: Printing request args")
    print(request.args)
    state = request.args.get('state')
    scope = request.args.get('scope')
    # In production this will be retrieved from the user cookie or flask session (same as our ecs-v2/v3a pplication does)
    email = 'abhishek@eye.space'
    authorization_code = jwt.encode({'email': email, 'scope': scope}, SECRET_KEY, algorithm='HS256')
    params = [('code', authorization_code), ('state', state)]
    uri = add_params_to_uri(request.args.get('redirect_uri'), params)
    return '', 302, [('Location', uri)]



@app.route("/token", methods=['POST'])
def token():
    print("token endpoint: Printing request headers")
    print(request.headers)
    print("token endpoint: Printing request args")
    print(request.args)
    print("token endpoint: Printing form")
    print(request.form)
    if request.form['client_secret'] != CLIENT_SECRET:
        return 'Incorrect client secret', 403
    now = int(time.time())
    user = jwt.decode(request.form['code'], SECRET_KEY, algorithms=['HS256'])
    id_payload = {
        'iss':'https://test-oidc.onrender.com',
        'aud': CLIENT_ID,
        'sub': "abhishek-123",
        'iat': now,
        'exp': now + 3600,
    }
    scopes = user["scope"].split(" ") # eg ["openid", "profile", "email"]
    if "email" in scopes:
        id_payload['email'] = "abhishek@eye.space"

    if "profile" in user["scope"]:
        id_payload["name"] = "Abhishek Das"
        id_payload["family_name"] = "Das"
        id_payload["given_name"] = "Abhishek"
        id_payload["middle_name"] = "Kumar"
        id_payload["nickname"] = "Abhishek"
        id_payload["preferred_username"] = "abhishek" # Maybe onedesk id
        id_payload["profile"] = "https://en.wikipedia.org/wiki/Iron_Man",
        id_payload["picture"] = "https://upload.wikimedia.org/wikipedia/en/4/47/Iron_Man_%28circa_2018%29.png"
        id_payload["website"] = "https://eye.space"
        id_payload["gender"] = ""
        id_payload["birthdate"] = ""
        id_payload["zoneinfo"] = "Australia/Adelaide"
        id_payload["locale"] = "en-AU"
        id_payload["updated_at"] = now
    token = {
        'access_token': "abc",
        'token_type': 'Bearer',
        "expires_in": 3600,
        'id_token': jwt.encode(id_payload, SECRET_KEY, algorithm='HS256'),
    }
    print("Printing id payload")
    print(id_payload)
    print("Printing token")
    print(token)
    default_json_headers = [
        ('Content-Type', 'application/json'),
        ('Cache-Control', 'no-store'),
        ('Pragma', 'no-cache'),
    ]
    return token, 200, default_json_headers


@app.route("/")
def home():
    return "Hello, Flask!"



@app.route("/healthz")
def healthz():
    return "OK"


if __name__ == "__main__":
    app.run(host="localhost", port=8080, debug=True)
