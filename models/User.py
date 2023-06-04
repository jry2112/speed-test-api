import models.datastore as datastore
# -------------------
# User Model
# First Name: String (3-25 chars)
# Last Name: String (3-25 chars)
# Email: String (3-255 chars)
# Device IDs: Array [Strings]
# Not Stored:
# ID, Self URL
# Users are created when signing up. 
# Users can be (un)assigned a Device
# -------------------

KIND = "User"
BASE_URL = ''

def add_user(data): 
    user_id = data[id]
    # If this is a new user, create the User
    if datastore.get_entity(BASE_URL, KIND, user_id):
        pass
    # If this a returning User, increment their login count
    new_user = datastore.add_entity(BASE_URL, KIND, data, user_id)
    return new_user

def get_user(user_id):
    target_user = datastore.get_entity(BASE_URL, KIND, user_id)
    return target_user

def get_users(filter_list=None):
    target_users = datastore.get_entities(BASE_URL, KIND, filter_list)
    return target_users