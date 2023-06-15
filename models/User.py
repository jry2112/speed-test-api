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


def add_user(data:dict):
     
    user_id = data['id']
    BASE_URL = data.pop('base_url')
    if datastore.get_entity(BASE_URL, KIND, user_id):
        return
    # If this is a new user, create the User
    new_user = datastore.add_entity(BASE_URL, KIND, data, user_id)
    return new_user

def get_user(user_id, base_url):
    target_user = datastore.get_entity(base_url, KIND, user_id)
    return target_user

def get_users(base_url, filter_list=None):
    target_users = datastore.get_entities(base_url, KIND, filter_list)
    return target_users

def get_all_users():
    base_url = ''
    users = datastore.get_entities(base_url, KIND)
    print("in users", users)
    result = {'user_ids': []}
    
    for user in users:
        result['user_ids'].append(user['id'])
    return result

def update_user_devices(base_url, user_id, device_id, add_device=True):
        # Get the user
        target_user = datastore.get_entity(base_url, KIND, user_id)
        # Update the device list and store it
        new_devices = target_user['devices']
        if add_device:
            new_devices.append(device_id)
        else:
            new_devices.remove(device_id)
        new_attr = {
            'devices': new_devices
        }
        
        result = datastore.update_entity(base_url, KIND, user_id, new_attr)
        return result