import models.datastore as datastore
# -------------------
# Test Model
# Test Start Time: Time
# Upload Speed: Float
# Download Speed: Float
# Latency: Float
# Device ID: String (Optional)
# Not Stored:
# ID, Self URL
# Tests can be created, viewed, updated, or deleted. 
# Tests are associated with a Device
# -------------------

KIND = "Test"


def add_test(data):
    base_url = data.pop('base_url')
    new_test = datastore.add_entity(base_url, KIND, data)
    return new_test

def get_test(test_id, base_url):
    target_test = datastore.get_entity(base_url, KIND, test_id)
    return target_test

def check_for_test(test_id):
    result = datastore.check_for_entity(KIND, test_id)
    return result

def get_tests_by_owner(device_id, q_offset, base_url):
    filter_list = [['device_id', '=', device_id]]
    
    results = datastore.get_entities_page(base_url, KIND, filter_list, q_offset)
    
    return results

def get_all_tests(q_offset, base_url):
    result = datastore.get_entities_page(base_url, KIND, None, q_offset)
    return result

def update_test(base_url, test_id, data):
    result = datastore.update_entity(base_url, KIND, test_id, data)
    return result

# Associate a tests with a different device
def update_test_device(test_id, device_id, base_url):
    cur_test = get_test(test_id, base_url)
    if cur_test:
        self_url = cur_test["self"]
        data = {'device_id': device_id}
        datastore.update_entity(self_url, KIND, test_id, data)
    else:
        return 404
    
def delete_test(test_id):
    if check_for_test(test_id):
        datastore.delete_entity(KIND, test_id)
    else:
        return 404
    
def get_test_device(test_id):
    return datastore.get_entity_attribute(KIND, test_id, "device_id")