from google.cloud import datastore

datastore_client = datastore.Client()
CURSOR_LIMIT = 5

def add_id_self_to_entity(base_url, entity):
    id = entity.key.id
    self_url = f"{base_url}/{id}"
    entity['id'] = id
    entity['self'] = self_url
    return entity

def get_client():
    return datastore_client

# Creates an Entity of Kind with given Data and stores in Datastore. Returns the entity with ID
def add_entity(base_url:str, kind:str, data:dict, entity_id=None):
    # Create a complete or incomplete key for an entity of kind Kind. An incomplete
    # key is one where Datastore will automatically generate an Id
    if entity_id:
        key = datastore_client.key(kind, entity_id)
    else:        
        key = datastore_client.key(kind)
    
    # Create an unsaved Entity object
    entity = datastore.Entity(key)

    # Apply attributes then save the Entity to Datastore
    entity.update(
        data
    )
    
    datastore_client.put(entity)
    # Add ID and self
    entity = add_id_self_to_entity(base_url, entity)
    
    return entity

# Gets all Entities of Kind and returns list. Entities include self URL
def get_entities(base_url, kind, filter_list=None):
    # Create a query against all of your objects of kind "Boat"
    query = datastore_client.query(kind=kind)
    
    if filter_list:
        # Unpack and add the filter(s)
        for filter in filter_list:
            query.add_filter(*filter)

    query_results = list(query.fetch())
    results = []
    # Add ID and self
    for i in range(len(query_results)):
        entity = query_results[i]
        entity = add_id_self_to_entity(base_url, entity)
        results.append(entity)

    return results

# Gets all Entities of Kind and returns list. Entities include self URL
def get_entities_page(base_url, kind, filter_list=None, q_offset=0):
    # Create a query against all of your objects of kind "Boat"
    query = datastore_client.query(kind=kind)
    
    if filter_list:
        # Unpack and add the filter(s)
        for filter in filter_list:
            query.add_filter(*filter)

    # Fetch the page
    query_iter = query.fetch(limit=CURSOR_LIMIT, offset=q_offset)
    page = next(query_iter.pages)
    query_results = list(page)
    
    # Get the total count of matching entities
    total_count = query_iter.num_results

    # If there's more - udpate the cursor and next URL
    if query_iter.next_page_token:
        next_offset = q_offset + CURSOR_LIMIT
        next_url = base_url + "?limit=" + str(CURSOR_LIMIT) + "&offset=" + str(next_offset)
    else:
        next_url = None
    # Add ID, self URL, and count to results
    results = {
        'entities': [],
        'count': total_count,
        'next': next_url
    }
    for entity in query_results:
        updated_entity = add_id_self_to_entity(base_url, entity)
        results['entities'].append(updated_entity)

    return results

# Gets an Entity of Kind and ID. Returns the Entity if found. Entities include self URL
def get_entity(base_url, kind, entity_id):
    key = datastore_client.key(kind, entity_id)
    target_entity = datastore_client.get(key)
    
    # Update ID and self attributes
    if target_entity:
        target_entity = add_id_self_to_entity(base_url, target_entity)
        return target_entity

# Updates an Entity of Kind and ID.
def update_entity(base_url, kind, entity_id, data:dict):
    with datastore_client.transaction():
        # Retrieve the entity
        key = datastore_client.key(kind, entity_id)
        entity = datastore_client.get(key)
        # Update attributes and save the changes
        for data_key, data_val in data.items():
            entity[data_key] = data_val
        datastore_client.put(entity)
    # TODO: Update the id and self
    entity = add_id_self_to_entity(base_url, entity)
    return entity

# Deletes an Entity of Kind and ID.
def delete_entity(kind, entity_id):
    key = datastore_client.key(kind, entity_id)
    datastore_client.delete(key)
    
# Retrieves designated attribute from entity
def get_entity_attribute(kind, entity_id, attribute):
    key = datastore_client.key(kind, entity_id)
    target_entity = datastore_client.get(key)
    if target_entity:
        return target_entity[attribute]
    
