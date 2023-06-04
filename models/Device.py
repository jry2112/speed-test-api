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
BASE_URL = ''

def add_device(data):
    new_device = datastore.add_entity(KIND, data)
    return new_device

def get_device(device_id):
    target_device = datastore.get_entity(BASE_URL, KIND, device_id)
    return target_device

def get_devices(owner_id, q_offset):
    filter_list = [['owner_id', '=', owner_id]]
    target_devices, next_url = datastore.get_entities_page(BASE_URL, KIND, filter_list, q_offset)
    return target_devices, next_url

def update_device_tests(device_id, test_id, add_test=False):
    cur_tests = datastore.get_entity_attribute(KIND, device_id, 'tests')
    if add_test:
        cur_tests.append(test_id)
    else:
        if test_id in cur_tests:
            cur_tests.remove(test_id)
    self_url = ''
    
    data = {'tests': cur_tests}
    datastore.update_entity(self_url, KIND, device_id, data)
    
def delete_device(device_id):
    if get_device(device_id):
        datastore.delete_entity(KIND, device_id)
    else:
        return 404