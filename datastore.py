from google.cloud import datastore

datastore_client = datastore.Client()

def get_client():
    return datastore_client

# Creates an Entity of Kind with given Data and stores in Datastore. Returns the entity with ID
def add_entity(kind:str, data:dict):
    # Create an incomplete key for an entity of kind Key. An incomplete
    # key is one where Datastore will automatically generate an Id
    key = datastore_client.key(kind)
    
    # Create an unsaved Entity object
    entity = datastore.Entity(key)

    # Apply attributes then save the Entity to Datastore
    entity.update(
        data
    )
    
    datastore_client.put(entity)
    entity['id'] = entity.key.id
    
    return entity

# Gets all Entities of Kind and returns list. Entities include self URL
def get_entities(base_url, kind):
    # Create a query against all of your objects of kind "Boat"
    query = datastore_client.query(kind=kind)
    results = list(query.fetch())
    for entity in results:
        entity["id"] = entity.key.id
    return results

# Gets an Entity of Kind and ID. Returns the Entity if found. Entities include self URL
def get_entity(base_url, kind, entity_id):
    key = datastore_client.key(kind, entity_id)
    target_entity = datastore_client.get(key)
    
    # TODO: Update ID and self attributes
    if target_entity:
        target_entity["id"] = target_entity.id

# Updates an Entity of Kind and ID.
def update_entity(self_url, kind, entity_id, data:dict):
    with datastore_client.transaction():
        # Retrieve the entity
        key = datastore_client.key(kind, entity_id)
        entity = datastore_client.get(key)
        # Update attributes and save the changes
        for data_key, data_val in data.items():
            entity[data_key] = data_val
        datastore_client.put(entity)
    # TODO: Update the id and self
    return entity

# Deletes an Entity of Kind and ID.
def delete_entity(kind, entity_id):
    key = datastore_client.key(kind, entity_id)
    datastore_client.delete(key)