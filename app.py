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
    state = request.args.get('state')
    # In production this will be retrieved from the user cookie or flask session (same as our ecs-v2/v3a pplication does)
    email = 'abhishek@eye.space'
    authorization_code = jwt.encode({'email': email}, SECRET_KEY, algorithm='HS256')
    params = [('code', authorization_code), ('state', state)]
    uri = add_params_to_uri(request.args.get('redirect_uri'), params)
    return '', 302, [('Location', uri)]



@app.route("/token", methods=['POST'])
def token():
    print("token endpoint: Printing request headers")
    print(request.headers)
    print("token endpoint: Printing entire request")
    print(request)
    print("token endpoint: Printing form")
    print(request.form)
    if request.headers['Authorization'] != f"Bearer {CLIENT_SECRET}":
        return 'Incorrect client secret', 403
    now = int(time.time())
    user = jwt.decode(request.form['code'], SECRET_KEY, algorithms=['HS256'])
    id_payload = {
        'iss':'https://eye.space',
        'aud': CLIENT_ID,
        'sub': user['email'],
        'iat': now,
        'exp': now + 3600,
        'auth_time': now,
    }
    token = {
        'access_token': "",
        'token_type': 'Bearer',
        "expires_in": 3600,
        'id_token': jwt.encode(id_payload, SECRET_KEY, algorithm='HS256'),
    }
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
