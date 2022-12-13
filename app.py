from utils import add_params_to_uri
import time
import string
import json
import logging
from jose import jwt
from flask import Flask, request

app = Flask(__name__)


SECRET_KEY = "ABCD"
CLIENT_ID = "foo123"
CLIENT_SECRET = "bar123"

log = logging.getLogger(__name__)
app.logger.setLevel(logging.DEBUG)


# MOCK_DB = { "1": {
#            "email": "tony@iron.man",
#            "name": "Tony Stark",
#            "family_name": "Stark",
#            "given_name": "Tony",
#            "middle_name": "Kumar",
#            "nickname": "Iron Man",
#            "preferred_username": "tstark", # Maybe onedesk id
#            "profile": "https://en.wikipedia.org/wiki/Iron_Man",
#            "picture": "https://upload.wikimedia.org/wikipedia/en/4/47/Iron_Man_%28circa_2018%29.png",
#            "website": "https://eye.space",
#            "gender": "",
#            "birthdate": "",
#            "zoneinfo": "Australia/Adelaide",
#            "locale": "en-AU",
#            "updated_at": 1670905096
# }
# }

# MOCK_DB = { "1": {
#            "email": "tony@iron.man",
#            "name": "Tony Stark",
#            "family_name": "Stark",
#            "given_name": "Tony",
#            "profile": "Tony Stark",
# }
# }

MOCK_DB = {
    "1": {
        "name": "Captain America",
        "email": "captain@america.avenger",
        "profile": "Captain America",
    }
}


def lookup_user(user_id):
    """
    TODO replace this with a call to the database
    """
    return MOCK_DB[user_id]


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
    id_payload = {
        "iss": "https://test-oidc.onrender.com",
        "aud": CLIENT_ID,
        "sub": "captain-123",
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
    return """
    <html>
    <head>
    <title>Test OIDC</title>
    </head>
    <body>
    <h1>Test OIDC</h1>
    <a href="https://test-oidc.onrender.com/authorize?client_id=foo123&response_type=code&scope=openid%20email%20profile&redirect_uri=https://app.onedesk.com/sso/openid&state=main_portal.3da2c61b-b810-491e-84d9-8e5a4c77a865">Login</a>
    </body>
    </html>
    """


@app.route("/healthz")
def healthz():
    return "OK"


if __name__ == "__main__":
    app.run(host="localhost", port=8080, debug=True)
