import models.datastore as datastore
# -------------------
# Device Model
# Device Name: String (3-25 chars)
# Tests: Array (Test_IDs)
# Not Stored:
# ID, Self URL
# Devices can be created, viewed, updated, or deleted. 
# Devices can be (un)assigned to Users. Devices are assigned Tests that they perform
# -------------------
KIND = "Device"
base_url = ''

def add_device(data):
    base_url = data.pop('base_url')
    new_device = datastore.add_entity(base_url, KIND, data)
    return new_device

def get_device(device_id, base_url):
    target_device = datastore.get_entity(base_url, KIND, device_id)
    return target_device

def check_for_device(device_id):
    result = datastore.check_for_entity(KIND, device_id)
    return result

def get_devices(owner_id, q_offset, base_url):
    filter_list = [['owner_id', '=', owner_id]]
    # Query for devices
    result = datastore.get_entities_page(base_url, KIND, filter_list, q_offset)   
    return result

def update_device(base_url, device_id, data):
    result = datastore.update_entity(base_url, KIND, device_id, data)
    return result

# Add or remove tests from a device
def update_device_tests(base_url, device_id, test_id, add_test=False):
    cur_tests = datastore.get_entity_attribute(KIND, device_id, 'tests')
    if add_test:
        cur_tests.append(test_id)
    else:
        if test_id in cur_tests:
            cur_tests.remove(test_id)
    # TODO: Create the self_url
    self_url = ''
    
    data = {'tests': cur_tests}
    datastore.update_entity(self_url, KIND, device_id, data)
    
def delete_device(device_id):
    if check_for_device(device_id):
        datastore.delete_entity(KIND, device_id)
    else:
        return 404
    
def get_device_owner(device_id):
    return datastore.get_entity_attribute(KIND, device_id, "owner_id")

def get_device_tests(device_id):
    return datastore.get_entity_attribute(KIND, device_id, "tests")