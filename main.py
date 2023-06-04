from flask import Flask, make_response, render_template, redirect, request, url_for, jsonify, _request_ctx_stack
from six.moves.urllib.request import urlopen
from jose import jwt

import json, requests
from os import environ as env
from werkzeug.exceptions import HTTPException
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from models import User, Device, Test

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
    
app = Flask(__name__)
app.secret_key = env.get('APP_SECRET_KEY')

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

DOMAIN = env.get("AUTH0_DOMAIN")

# configure Authlib to handle authentication with Auth0
auth0 = oauth.register(
    'auth0',
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
     server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
# Returns decoded
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=env.get("AUTH0_CLIENT_ID"),
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

'''
    # Sample JWT User Profile
    {
    'access_token': 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiaXNzIjoiaHR0cHM6Ly9kZXYtOGR0Z2NiY2xzN2t1Y25wYS51cy5hdXRoMC5jb20vIn0..yQR_kR6VZ_a989tP.kG_7VvpuzamZ3-Mr7SWb2czG4pvEOGACM03hldV2t8gzAIc4qiMQYNUbC5PmVOWKF4VbQKhFMQPBZ7b7YrceXo_j2H1znAJsv69wKNzTtWeYrj7Cg89RsZvlg8MdIyQ_IguU7MOiDUt_qp2bKUH0_VTHukl0hFA9hL72nna201GUT2BrY0QjNWIz_Dk99xB6lLCq43Syajly3YCRD3G3Qq2yn4N28s2lXXc7ysz5ixOLxSI0MwDtf4SRsLxtEmY2W9nNnLAZVp1j-ZxT6sz5-9bZtb32DV7VHfNM-okxdZDBGndbD_V8ccL_rwo8O4blsUVsZ5D9RXaIq8FTojOoHBOi.CcNy5w2oLz_xB6MdfTJTqA',
    'id_token': 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjlaeUZWeVF6ODBaeUN4NE9rX2djciJ9.eyJuaWNrbmFtZSI6InRlc3QiLCJuYW1lIjoidGVzdEBzYW1wbGUuY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyL2EyNjVkNWI4M2YwOWEyNmY3NTlmMDlhOTMxNjAxYjhmP3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGdGUucG5nIiwidXBkYXRlZF9hdCI6IjIwMjMtMDYtMDRUMDQ6MTg6NTUuNzA0WiIsImVtYWlsIjoidGVzdEBzYW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJpc3MiOiJodHRwczovL2Rldi04ZHRnY2JjbHM3a3VjbnBhLnVzLmF1dGgwLmNvbS8iLCJhdWQiOiIxak5ENXlWVW1rT2dlS2VYQjNZSVF1Z0l2d1hBdFFaRyIsImlhdCI6MTY4NTg1MjMzOSwiZXhwIjoxNjg1ODg4MzM5LCJzdWIiOiJhdXRoMHw2NDY1NjM4MWMzZjNhOGUwOGFjZjc4ZTQiLCJzaWQiOiJkX1RZbFE3QU8xSnJzc0dkNElvLUJSZXEzeGVtMlp3SSIsIm5vbmNlIjoidVJuaFVpNmxnWG9PbWFRbkg5am4ifQ.oE1kUaBtaFgiWUDDHWNnRsKt7X007jrxXw29UK8s_CJMIYCyOMH_kezTKB82Ztro2AURXKDYXscaB8X68dWEIv1w6RaTNYdOgyQnH_F4At4xykRxKS3n-ghkTsj-kQUnBFnhyIWKi5eXBeWk_77glaysDXChhxDMxf-lCVkVJ2-s027KIwtM2eA8Kgcf_iiy5eVYKqx1zYNpYTNt_qScCdIKxyb5oLb3R8KnquYk2QZtgXQNJP0v8YwMoThareEYYhcg3l1dUyFKB8QcbVoTa6gPl_J5xalKbe1EP2KM9LJonDfqyqL-trErZ4OAGUA01TGVxvTlFR-m9-ZktOXiNg',
    'scope': 'openid profile email',
    'expires_in': 86400,
    'token_type': 'Bearer',
    'expires_at': 1685938739,
    'userinfo': {
        'nickname': 'test',
        'name': 'test@sample.com',
        'picture': 'https://s.gravatar.com/avatar/a265d5b83f09a26f759f09a931601b8f?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fte.png',
        'updated_at': '2023-06-04T04:18:55.704Z',
        'email': 'test@sample.com',
        'email_verified': False,
        'iss': 'https://dev-8dtgcbcls7kucnpa.us.auth0.com/',
        'aud': '1jND5yVUmkOgeKeXB3YIQugIvwXAtQZG',
        'iat': 1685852339,
        'exp': 1685888339,
        'sub': 'auth0|64656381c3f3a8e08acf78e4',
        'sid': 'd_TYlQ7AO1JrssGd4Io-BReq3xem2ZwI',
        'nonce': 'uRnhUi6lgXoOmaQnH9jn'
    }
}
'''


@app.route('/')
def root():
    return render_template(
        'index.html', user=None)

# Auth0 Login Routing    
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )
    
@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    
    # Store the JWT in a cookie and redirect to the User Info page
    user_id = token['userinfo']['sub']
    resp = make_response(redirect(f"/user/{user_id}"))
    token = json.dumps(token)
    resp.set_cookie('session_jwt', token, httponly=True)
    return resp
# -------------------
# USER Routes
# -------------------
# Display the JWT after login
# Store the User in the Database
@app.route("/user/<string:user_id>")
def show_user(user_id):
    base_url = f"{request.url}"
    cur_jwt = request.cookies.get('session_jwt')
    cur_jwt = json.loads(cur_jwt)
    # Update Users
    user_data = {
        'id': cur_jwt['userinfo']['sub'],
        'email': cur_jwt['userinfo']['name'],
        'base_url': base_url
    }
    User.add_user(user_data)
    # Show the user's JWT
    return render_template(
        'index.html', user=cur_jwt)

# -------------------
# DEVICE Routes
# -------------------
# GET all devices and CREATE a device
@app.route('/devices', methods=['GET', 'POST'])
def devices():
    base_url = f"{request.url}"
    if request.method == 'GET':
        query_offset = int(request.args.get('offset', '0'))
        owner_id = ''
        devices, next_url = Device.get_devices(owner_id, query_offset)
        pass
    elif request.method == 'POST':
        pass
    else:
        pass
    
@app.route('/devices/<int:device_id>', methods=['PUT', 'PATCH', 'DELETE'])
def devices(device_id):
    base_url = f"{request.url}"
    if request.method == 'PUT':
        pass
    elif request.method == 'PATCH':
        pass
    elif request.method == 'DELETE':
        pass
    else:
        pass
    
    return render_template(
        'index.html', user=None)

# -------------------    
# TEST Routes
# -------------------

@app.route('/tests', methods=['GET', 'POST'])
def devices():
    base_url = f"{request.url}"
    if request.method == 'GET':
        device_id = ''
        query_offset = int(request.args.get('offset', '0'))
        devices, next_url = Test.get_tests(device_id, query_offset)
        pass
    elif request.method == 'POST':
        pass
    else:
        pass
    
@app.route('/tests/<int:test_id>', methods=['PUT', 'PATCH', 'DELETE'])
def devices(device_id):
    base_url = f"{request.url}"
    if request.method == 'PUT':
        pass
    elif request.method == 'PATCH':
        pass
    elif request.method == 'DELETE':
        pass
    else:
        pass
    
    return render_template(
        'index.html', user=None)
    
    
if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)