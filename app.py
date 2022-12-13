"""
Flask implementation of an OpenID Connect (OIDC) Authorization Server.
It has two endpoints:

1. /auothorize: This is the endpoint that the OIDC client will use to authenticate users and returns an authorization code.
2. /token: This is the endpoint that the OIDC client will use to exchange the authorization code for an access token.

The code is based on the Authorization Code Flow through the following steps:

1. Client prepares an Authentication Request containing the desired request parameters.
2. Client sends the request to the Authorization Server.
3. Authorization Server Authenticates the End-User.
4. Authorization Server obtains End-User Consent/Authorization.
5. Authorization Server sends the End-User back to the Client with an Authorization Code.
6. Client requests a response using the Authorization Code at the Token Endpoint.
7. Client receives a response that contains an ID Token and Access Token in the response body.
8. Client validates the ID token and retrieves the End-User's Subject Identifier.
"""

from utils import add_params_to_uri
import os, time
import string
import random
import logging
from jose import jwt
from flask import Flask, redirect, request, render_template

app = Flask(__name__)

default_json_headers = [
    ('Content-Type', 'application/json'),
    ('Cache-Control', 'no-store'),
    ('Pragma', 'no-cache'),
]

user_info = {
    'id': '123',
    'name': 'Abhishek Das',
    'email': 'abhishek@eye.space',
}
authorization_code = None

log = logging.getLogger(__name__)
app.logger.setLevel(logging.DEBUG)

client = {
    'client_id': 'foo123',
    'client_secret': 'bar123',
    'redirect_uri': 'https://app.onedesk.com/sso/openid',
    'scopes': 'openid email profile',
    'response_type': 'code',
    'token_endpoint_auth_method': 'client_secret_basic'
}
UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits

def verify_scope(scope):
    log.debug('Verifying scope: %s', scope)
    scopes = scope.split(' ')
    for s in scopes:
        if s not in client['scopes'].split(' '):
            return False
    return True

def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    rand = random.SystemRandom()
    return ''.join(rand.choice(chars) for _ in range(length))


def generate_id_token():
    #Header.Payload.Signature
    auth_time=None
    exp = 3600
    now = int(time.time())
    if auth_time is None:
        auth_time = now

    payload = {
        'iss':'https://eye.space',
        'aud': client['client_id'],
        'sub': user_info['email'],
        'iat': now,
        'exp': now + exp,
        'auth_time': auth_time,
    }
    private_key = open('jwt-key').read()
    return jwt.encode(payload, private_key, algorithm='RS256')
    # key = 'secret'
    # # if using RS256 algorithm, use the private key to sign the token
    # return jwt.encode(payload, key, algorithm='HS256')


def validate_authorization_request(request):
    log.debug('Validating authorization request: %s', request)
    # check if the client_id is valid
    if request['client_id'] != client['client_id']:
        log.debug('Invalid client_id')
        return False

    # check if the redirect_uri is valid
    if request['redirect_uri'] != client['redirect_uri']:
        log.debug('Invalid redirect_uri')
        return False

    # check if the response_type is valid
    if request['response_type'] != client['response_type']:
        log.debug('Invalid response_type')
        return False

    # check if the scope is valid
    if not verify_scope(request['scope']):
        log.debug('Invalid scope')
        return False
    return True

def authenticate_token_endpoint_client():
    log.debug('Authenticating token endpoint client')
    auth = request.authorization
    if not auth:
        return False
    if auth.username != client['client_id']:
        return False
    if auth.password != client['client_secret']:
        return False
    return True

@app.route("/authorize")
def authorize():
    # get the authorization request parameters
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    scope = request.args.get('scope')
    state = request.args.get('state')
    request_param = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': scope
    }

    # validate the authorization request
    if not validate_authorization_request(request_param):
        return 'Invalid authorization request', 400
    
    # generate the authorization code
    global authorization_code 
    log.debug('Generating authorization code')
    authorization_code = generate_token()

    params = [('code', authorization_code)]
    params.append(('state', state))
    # get redirect_uri from client dic
    print(f"params: {params}")
    redirect_uri = client['redirect_uri']
    uri = add_params_to_uri(redirect_uri, params)
    headers = [('Location', uri)]
    # return header with 302 status code
    return '', 302, headers
    # return 302, '', headers
    # return redirect(uri, code=302)
  

  

@app.route("/token", methods=['POST'])
def token():
    log.debug('Generating token')
    # verify the client
    # if not authenticate_token_endpoint_client():
    #     return 'Invalid client', 401
    
    log.debug('Verifying grant type')
    # verify the grant_type is authorization_code
    if request.form['grant_type'] != 'authorization_code':
        return 'Invalid grant type', 400
    # verify the authorization code in the request is the same as the one generated
    log.debug('Verifying authorization code')
    if request.form['code'] != authorization_code:
        return 'Invalid authorization code', 400
    log.debug('Generating token')
    # generate the id_token
    id_token = generate_id_token()

    token = {
        'access_token': generate_token(),
        'token_type': 'Bearer',
        "expires_in": 3600,
        'id_token': id_token
    }
    return token, 200, default_json_headers


@app.route("/")
def home():
    return "Hello, Flask!"



@app.route("/healthz")
def healthz():
    return "OK"



if __name__ == "__main__":
    app.run(host="localhost", port=8080, debug=True)


