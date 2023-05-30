from datastore import get_client, make_entity

datastore_client = get_client()

# Model for Load Entity
# Loads can be placed on a boat and have the following functionality:
# Create a load, View a load, View all loads, Delete a load, Manage a load


def add_load(volume: int, item: str, creation_date: str):
    # Create an incomplete key for an entity of kind "Load". An incomplete
    # key is one where Datastore will automatically generate an Id
    key = datastore_client.key("Load")

    # Create an unsaved Load Entity object
    load = make_entity(key)

    # Apply attributes then save the Boat entity to Datastore
    load.update(
        {
            "volume": volume,
            "carrier": None,
            "item": item,
            "creation_date": creation_date
        }
    )
    
    datastore_client.put(load)
    result = load, load.id
    
    return result

def delete_load(load_id):
    # Delete the load
    key = datastore_client.key('Load', load_id)
    datastore_client.delete(key)
    return

def get_loads(base_url, q_limit, q_offset):
    # Create a query against all of your objects of kind "Load"
    query = datastore_client.query(kind="Load")
    l_iterator = query.fetch(limit=q_limit, offset=q_offset)
    pages = l_iterator.pages
    results = list(next(pages))
    # If there's more - udpate the offset and next URL
    if l_iterator.next_page_token:
        next_offset = q_offset + q_limit
        next_url = base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
    else:
        next_url = None
    # Store the ID and self URL
    for load in results:
        id = load.key.id
        load["id"] = id
        load["self"] = f"{base_url}/{id}"
        
    return results, next_url

def get_a_load(load_id, url=None):
    # Fetch the Load with the given ID
    key = datastore_client.key("Load", load_id)
    target_load = datastore_client.get(key)
    if target_load and url:
        target_load["id"] = target_load.id
        target_load["self"] = f"{url}"
    return target_load

def unload_load(load_id):
    key = datastore_client.key("Load", load_id)
    target_load = datastore_client.get(key)
    if target_load:
        target_load["carrier"] = None
    # Save the load
    datastore_client.put(target_load)
    return target_load

def load_load(load_id, boat_id):
    key = datastore_client.key("Load", load_id)
    target_load = datastore_client.get(key)
    carrier = {"id": boat_id}
    # Update the carrier
    if target_load:
        target_load["carrier"] = carrier
    # Save the load
    datastore_client.put(target_load)
    return target_load