import models.datastore as datastore
# -------------------
# Test Model
# Test Start Time: Time
# Upload Speed: Float
# Download Speed: Float
# Latency: Float
# Device ID: String
# Not Stored:
# ID, Self URL
# Tests can be created, viewed, updated, or deleted. 
# Tests are associated with a Device
# -------------------

KIND = "Test"
BASE_URL = ''

def add_test(data):
    new_test = datastore.add_entity(KIND, data)
    return new_test

def get_test(test_id):
    target_test = datastore.get_entity(BASE_URL, KIND, test_id)
    return target_test

def get_tests(device_id, q_offset):
    filter_list = [['device_id', '=', device_id]]
    target_tests, next_url = datastore.get_entities_page(BASE_URL, KIND, filter_list, q_offset)
    return target_tests, next_url

# Associate a tests with a different device
def update_test_device(test_id, device_id):
    if get_test(test_id):
        self_url = ''
        data = {'device_id': device_id}
        datastore.update_entity(self_url, KIND, test_id, data)
    else:
        return 404