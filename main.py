from flask import Flask, make_response, render_template, redirect, request, url_for, jsonify, _request_ctx_stack
from six.moves.urllib.request import urlopen
from jose import jwt

import json, requests
from os import environ as env
from werkzeug.exceptions import HTTPException
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from datetime import datetime
import string
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
    'access_token': '',
    'id_token': '',
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
        'iss': '',
        'aud': '',
        'iat': 1685852339,
        'exp': 1685888339,
        'sub': 'auth0|',
        'sid': '',
        'nonce': ''
    }
}
'''
# ----------------------------------------------------------------------
# 
# REQUEST DATA VALIDATION HELPERS
# Validate data for creating Users, Devices, and Tests
#
# ---------------------------------------------------------------------- 
MAX_STRING = 255

def validate_user_data(data):
    valid = False
    user_keys =  {
        'id': str,
        'email': str,
        'base_url': str
    }
    # Validate length of data
    if len(user_keys) == len(data):
        # Validate keys & values of data
        for key, data_type in user_keys.items():
            if type(data[key]) != data_type or len(data[key]) > MAX_STRING:
                break
        valid = True
    return valid


def validate_device_data(data:dict, put_request=True):
    valid = False
    device_keys = {
        "DeviceName": str,
        "DeviceType":["E9"],
        "DeviceBrand":["Dell"]   
    }
    if put_request:
        # Validate length of data
        if len(device_keys) == len(data):
            # Validate keys & values of data
            if type(data["DeviceName"]) == device_keys["DeviceName"]:
                if len(data["DeviceName"]) < MAX_STRING:
                    if data["DeviceType"] in device_keys["DeviceType"]:
                        if data["DeviceBrand"] in device_keys["DeviceBrand"]:
                            valid = True
    else:
        valid_patch = True
        # Validate the PATCH request
        for key, value in data.items():
            if key not in device_keys:
                valid_patch = False
                break
            if key == "DeviceName":
                if type(value) != str or len(value) > MAX_STRING:
                    valid_patch = False
                    break
            elif key == "DeviceType":
                if value not in device_keys["DeviceType"]:
                    valid_patch = False
                    break
            elif key == "DeviceBrand":
                if value not in device_keys["DeviceBrand"]:
                    valid_patch = False
                    break
                
        valid = valid_patch        
                    
    return valid
    


def validate_test_data(data, put_request = True):
    valid = True    
    test_keys = {
        "TestName": ["ndt5"],
        "TestStartTime": datetime,
        "TestEndTime": datetime,
        "MurakamiLocation": str,
        "MurakamiConnectionType": ["wired", "wireless"],
        "MurakamiNetworkType": ["home", "commercial"],
        "ServerName": str,
        "ServerIP": str,
        "ClientIP": str,
        "DownloadUUID": str,
        "DownloadValue": float,
        "DownloadUnit": ["Mbit/s"],
        "UploadValue": float,
        "UploadUnit": ["Mbit/s"],
        "DownloadRetransValue": float,
        "DownloadRetransUnit": ["%"],
        "MinRTTValue": float,
        "MinRTTUnit": ["ms"],
        "device_id": None
    }
    
    
    fixed_value_keys = ["TestName", "MurakamiConnectionType", "MurakamiNetworkType", "DownloadUnit", "UploadUnit", "DownloadRetransUnit", "MinRTTUnit"]
    # Verify device_id
    if data["device_id"] is not None:
       # Add device_id to test keys and validate device
        test_keys['device_id'] = str 
        device_id = data['device_id']
        if Device.check_for_device(device_id) != True:  
            valid = False
            return valid
    
            
    if put_request:
        # Validate length of data
        if len(test_keys) == len(data):
            for key, value in data.items():
                if key not in test_keys and key != 'device_id':
                    print(key)
                    valid = False
                    break
                if key in fixed_value_keys:
                    # Improper value set
                    if value not in test_keys[key]:
                        print(key, value)
                        valid = False
                        break
                else:
                    # Handle dynamic strings and float value
                    if (type(value) != test_keys[key] or (type(value) == str and len(value) > MAX_STRING)) and key != 'device_id':
                        print(type(key), key, value)
                        valid = False
                        break

        else:
            print(len(test_keys), len(data))
            valid = False    
    else:
        if len(data) > len(test_keys):
            valid = False
        else:
            for key, value in data.items():
                if key not in test_keys:
                    
                    valid = False
                    break
                if key in fixed_value_keys:
                    print(key)
                    # Improper value set
                    if value not in test_keys[key]:
                        print(value, key)
                        print(test_keys[key])
                        valid = False
                        break
                else:
                    # Handle dynamic strings and float value
                    if (type(value) != test_keys[key] or (type(value) == str and len(value) > MAX_STRING)) and key != 'device_id':
                        print(value, key)
                        print(test_keys[key])
                        valid = False
                        break       
    
    return valid    

def create_response(data, status_code):
    response = app.response_class(response=json.dumps(data), 
                                  status=status_code,
                                  mimetype='application/json')
    return response 

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
def add_user(user_id):
    base_url = f"{request.url}"
    cur_jwt = request.cookies.get('session_jwt')
    cur_jwt = json.loads(cur_jwt)
    # Update Users
    user_data = {
        'id': cur_jwt['userinfo']['sub'],
        'email': cur_jwt['userinfo']['name'],
        'devices': [],
        'base_url': base_url
    }
    print(user_data)
    new_user = User.add_user(user_data)
    print(new_user)
        # Show the user's JWT
    return render_template(
            'index.html', user=cur_jwt)
        
# GET all users
@app.route('/users', methods=['GET'])
def get_users():
    if request.method == 'GET':
        result = User.get_all_users()
        print("fetched users", result)
        if result:
            response_json = result
            status_code = 200
        else:
            # Error getting users
            response_json = {"Error": "Unable to process request."}
            status_code = 400
            pass
    else:
        response_json = {"Error": 'Method not recogonized.'}
        status_code = 405
        
    return create_response(response_json, status_code)

# -------------------
# DEVICE Routes
# -------------------
# GET all devices and CREATE a device
@app.route('/devices', methods=['GET', 'POST'])
def devices():
    base_url = f"{request.host_url}devices"
    # Missing or invalid JWT
    # Validate the JWT
    payload = verify_jwt(request)
    if not payload:
        # Return invalid JWT response
        response_json = {"Error": "Please provide valid JWT"}
        status_code = 401
    elif payload:
        # Grab the owner ID (sub)
        owner_id = payload['sub']
        print(owner_id)
        mime_types = request.accept_mimetypes
        print(mime_types)
        if 'application/json' not in mime_types:
            # Invalid Mimetype
            status_code = 406
            response_json = {"Error": "Not Acceptable - Invalid Accept Header"}
            response = create_response(response_json, status_code)
            return response        
        # Get all Devices for the Owner
        if request.method == 'GET':
            # Verify the owner exists
            owner = User.get_user(owner_id, base_url)
            if owner:
                device_url = f"{request.host_url}devices"
                query_offset = int(request.args.get('offset', '0'))
                result = Device.get_devices(owner_id, query_offset, device_url)
                print(result)
                for device in result["entities"]:
                    print(device["tests"])
                    for i in range(len(device["tests"])):
                        test_id = device["tests"][i]
                        device["tests"][i] = {"id": test_id,
                                "self": f"{request.host_url}tests/{test_id}"}
                response_json = result
                status_code = 200
            else:
                # Invalid Owner ID provided
                status_code = 404
                response_json = {"Error": "Invalid User ID provided."}
                    
        # Create a device
        elif request.method == 'POST':
            # Request must be JSON
            content = request.get_json()
            if validate_device_data(content):
                # add owner ID, test list then store the device
                content['owner_id'] = owner_id
                content['tests'] = []
                content['base_url'] = f"{request.host_url}devices"
                
                result = Device.add_device(content)
                if result:
                    status_code = 201
                    response_json = result
                    print(result)
            else:
                # Invalid data provided
                response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
                status_code = 400
        else:
            # Invalid request provided
            response_json = {"Error": 'Method not recogonized.'}
            status_code = 405
            
        response = create_response(response_json, status_code)
        return response

    
@app.route('/devices/<int:device_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def manage_a_device(device_id):
    base_url = f"{request.host_url}devices"
    # Missing or invalid JWT
    status_code = 401
    response_json = {"Error": "Please provide valid JWT"}
    # Validate the JWT
    payload = verify_jwt(request)
    if payload:
        owner_id = payload['sub']
        
        if Device.check_for_device(device_id) == False:
            response_json = {"Error": "No device with this device_id exists"}
            status_code = 404
        else:    
            if request.method == 'GET':
                mime_types = request.accept_mimetypes
                if 'application/json' not in mime_types:
                    # Invalid Mimetype
                    status_code = 406
                    response_json = {"Error": "Not Acceptable - Invalid Accept Header"}
                    response = create_response(response_json, status_code)
                    return response
                else:
                    device = Device.get_device(device_id, base_url)
                    if device:
                        # Verify ownership
                        if device["owner_id"] == owner_id:
                            print("verified ownership")
                            
                            for i in range(len(device["tests"])):
                                test_id = device["tests"][i]
                                device["tests"][i] = {"id": test_id,
                                    "self": f"{request.host_url}tests/{test_id}"}
                            response_json = device
                            status_code = 200
                        else:
                            response_json = {"Error": "Unauthorized action."}
                            status_code = 403
                    else:
                        # Invalid device ID
                        response_json = {"Error": "No device with this device_id exists"}
                        status_code = 404
                
                
            elif request.method == 'PUT':
                mime_types = request.accept_mimetypes
                if 'application/json' not in mime_types:
                    # Invalid Mimetype
                    status_code = 406
                    response_json = {"Error": "Not Acceptable - Invalid Accept Header"}
                else:
                    content = request.get_json()
                    # Verify request data and validate ownership
                    if validate_device_data(content) == False:
                        response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
                        status_code = 400
                        
                    elif owner_id != Device.get_device_owner(device_id):
                        response_json = {"Error": "Unauthorized action."}
                        status_code = 403
                    # Update the device
                    else:
                        # Update the tests
                        cur_tests = Device.get_device(device_id, base_url)["tests"]
                        if cur_tests:
                            test_url = f"{request.host_url}tests"
                            for test_id in cur_tests:
                                Test.update_test_device(test_id, None, test_url)
                        # Update device
                        Device.update_device(base_url, device_id, content)
                        response_json = {}
                        status_code = 204
                        
                    
            elif request.method == 'PATCH':
                mime_types = request.accept_mimetypes
                if 'application/json' not in mime_types:
                    # Invalid Mimetype
                    status_code = 406
                    response_json = {"Error": "Not Acceptable - Invalid Accept Header"}
                else:
                    content = request.get_json()
                    
                    # Validate data and ownership
                    if validate_device_data(content, put_request=False) == False:
                        response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
                        status_code = 400
                        
                    elif owner_id != Device.get_device_owner(device_id):
                        response_json = {"Error": "Unauthorized action."}
                        status_code = 403
                    # Update the device
                    else:
                        if "tests" in content:
                            cur_tests = Device.get_device(device_id, base_url)["tests"]
                            if cur_tests:
                                test_url = f"{request.host_url}tests"
                                for test_id in cur_tests:
                                    Test.update_test_device(test_id, None, test_url)
                        Device.update_device(base_url, device_id, content)
                        response_json = {}
                        status_code = 204
                    
                
            elif request.method == 'DELETE':
                mime_types = request.accept_mimetypes
                if 'application/json' not in mime_types:
                    # Invalid Mimetype
                    status_code = 406
                    response_json = {"Error": "Not Acceptable - Invalid Accept Header"}
                else:
                    if owner_id != Device.get_device_owner(device_id):
                        response_json = {"Error": "Unauthorized action."}
                        status_code = 403
                    else:
                        # update the device's tests
                        cur_tests = Device.get_device_tests(device_id)
                        if cur_tests:
                            test_url = f"{request.host_url}tests"
                            for test_id in cur_tests:
                                Test.update_test_device(test_id, None, test_url)
                        Device.delete_device(device_id)
                        response_json = {}
                        status_code = 204
                    
            else:
                # Invalid request provided
                response_json = {"Error": 'Method not recogonized.'}
                status_code = 405
                
    else:
        # Invalid Authorization
        response_json = {"Error": "Please provide valid JWT"}
        status_code = 401
    
    response = create_response(response_json, status_code)
    
    return response

# -------------------    
# TEST Routes
# -------------------
timestamp_keys = ["TestStartTime", "TestEndTime"]

@app.route('/tests', methods=['GET', 'POST'])
def tests():
    base_url = f"{request.host_url}tests"
     
    if request.method == 'GET':
        query_offset = int(request.args.get('offset', '0'))
        result = Test.get_all_tests(query_offset, base_url)
        if result:
            for test in result["entities"]:
                for key in timestamp_keys:
                    if key in test:
                        dt = test[key]
                        print(key, dt)
                        test[key] = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
                
            response_json = result
            status_code = 200
        else:
            # Error retrieving tests
            response_json = {"Error": "Error retrieving results"}
            status_code = 404
        pass
    elif request.method == 'POST':
        content = request.get_json()
        # Get the device id if included
        if 'device_id' in content:
            device_id = content['device_id']
            if Device.check_for_device(device_id) == False:
                response_json = {"Error": "No device with this device_id exists."}
                status_code = 404
                response = create_response(response_json, status_code)
                return response
        else:
            content['device_id'] = None
            
        # Convert timestamp to a datetime object
        for key in timestamp_keys:
            date_string = content[key]
            try:
                content[key] = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f")
                print(key, type(content[key]))
            except:
                # Invalid data provided
                response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
                status_code = 400
                break
        
        if validate_test_data(content):
            content["base_url"] = f"{request.host_url}tests"
            test = Test.add_test(content)
            for key in timestamp_keys:
                dt = content[key]
                test[key] = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
            response_json = test
            status_code = 201
        else:
            # Invalid data provided
            response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
            status_code = 400
    else:
        # TODO: Invalid request provided
        response_json = {"Error": 'Method not recogonized.'}
        status_code = 405
        pass
    
    response = create_response(response_json, status_code)
    return response
    
@app.route('/tests/<int:test_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def manage_a_test(test_id):
    base_url = f"{request.host_url}tests"
    mime_types = request.accept_mimetypes
    status_code = None
    if 'application/json' not in mime_types:
            # Invalid Mimetype
            status_code = 406
            response_json = {"Error": "Not Acceptable - Invalid Accept Header"}
            response = create_response(response_json, status_code)
            return response
        
    if Test.check_for_test(test_id) == False:
        response_json = {"Error": "No test exists with this test_id."}
        status_code = 404
        response = create_response(response_json, status_code)
        return response
        
    if request.method == 'GET':
        test = Test.get_test(test_id, base_url)
        if test:
            for key in timestamp_keys:
                dt = test[key]
                test[key] = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
            response_json = test
            status_code = 200
        else:
            response_json = {"Error": "No test exists with this test_id."}
            status_code = 404
    elif request.method == 'PUT':
        # make changes to all of the test fields
        mime_types = request.accept_mimetypes
        if 'application/json' not in mime_types:
            # Invalid Mimetype
            status_code = 406
            response_json = {"Error": "Not Acceptable - Invalid Accept Header"}
        else:
            content = request.get_json()
            if "device_id" in content:
                if Device.check_for_device(content["device_id"]) == False:
                    response_json = {"Error": "The request object contains an invalid device_id."}
                    status_code = 404
                    response = create_response(response_json, status_code)
                    return response
                else:
                    for key in timestamp_keys:
                        print(key)
                        date_string = content[key]
                        # print(date_string)
                    try:
                        content[key] = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f")
                        print(key, type(content[key]), content[key])
                    except:
                        # Invalid data provided
                        response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
                        status_code = 400
                        response = create_response(response_json, status_code)
                        return response
                    content["TestStartTime"] = datetime.strptime(content["TestStartTime"], "%Y-%m-%dT%H:%M:%S.%f")
                    
                    # for key, value in content.items():
                        # print(key, type(value))
                    # Verify request data and validate ownership
                    if validate_test_data(content, put_request=True) == False:
                        response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
                        status_code = 400
                    
            
                if not status_code:
                    device_url = f"{request.host_url}devices"
                    # Update the device's tests
                    # Add to new device
                    if content["device_id"] != None:
                        Device.update_device_tests(device_url, content["device_id"], test_id, add_test=True) 
                    # Remove from old device
                    old_device_id = Test.get_test_device(test_id)
                    if old_device_id:
                        Device.update_device_tests(device_url, old_device_id, test_id, add_test=False)   
                    # Update the test
                    Test.update_test(base_url, test_id, content)
                    response_json = {}
                    status_code = 204
        
    elif request.method == 'PATCH':
        # make changes to some of the test fields
        mime_types = request.accept_mimetypes
        if 'application/json' not in mime_types:
            # Invalid Mimetype
            status_code = 406
            response_json = {"Error": "Not Acceptable - Invalid Accept Header"}
        else:
            content = request.get_json()
            for key in timestamp_keys:
                if key in content:
                    print(key)
                    try:
                        date_string = content[key]
                        content[key] = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%f")
                        print(key, type(content[key]), content[key])
                    except:
                        # Invalid data provided
                        response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
                        status_code = 400
                        response = create_response(response_json, status_code)
                        return response
            # Verify request data and validate ownership
            if validate_test_data(content, put_request=False) == False:
                response_json = {"Error": "The request object is missing at least one of the required attributes or has an additional attribute."}
                status_code = 400
                response = create_response(response_json, status_code)
                return response
            
            if "device_id" in content:
                if Device.check_for_device(content["device_id"]) == False:
                    response_json = {"Error": "The request object contains an invalid device_id."}
                    status_code = 404
                    response = create_response(response_json, status_code)
                    return response
                else:
                    device_url = f"{request.host_url}devices"
                    # Update the device's tests
                    # Add to new device
                    if content["device_id"] != None:
                        Device.update_device_tests(device_url, content["device_id"], test_id, add_test=True) 
                    # Remove from old device
                    old_device_id = Test.get_test_device(test_id)
                    if old_device_id:
                        Device.update_device_tests(device_url, old_device_id, test_id, add_test=False)
                
            # Update the test        
            Test.update_test(base_url, test_id, content)
            response_json = {}
            status_code = 204
        
    elif request.method == 'DELETE':
        test = Test.get_test(test_id, base_url)
        if test:
            # Update device's test list
            device_id = test["device_id"]
            if device_id:
                device_url = f"{request.host_url}devices"
                Device.update_device_tests(device_url, device_id, test_id)
            # Delete the test
            Test.delete_test(test_id)
            response_json = {}
            status_code = 204
        else:
            # Invalid test_id
            response_json = {"Error": "No test with this test_id exists"}
            status_code = 404
    else:
        # Invalid request provided
        response_json = {"Error": 'Method not recogonized.'}
        status_code = 405
        
    
    response = create_response(response_json, status_code)
    return response
    
    
if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
