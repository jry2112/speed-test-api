from datastore import get_client, make_entity

datastore_client = get_client()

# Model for Boat Entity
# Boats carry a load and have the following functionality:
# Create a boat, View a boat, view all boats, delete a boat
# View all loads for a given boat

# Boats must have name, type, and length. They do not have a load at start
def add_boat(name: str, type: str, length: int):
    # Create an incomplete key for an entity of kind "Boat". An incomplete
    # key is one where Datastore will automatically generate an Id
    key = datastore_client.key("Boat")

    # Create an unsaved Boat Entity object
    boat = make_entity(key)

    # Apply attributes then save the Boat entity to Datastore
    boat.update(
        {
            "name": name,
            "type": type,
            "length": length,
            "loads": []
        }
    )
    datastore_client.put(boat)
    result = boat, boat.id
    
    return result

def get_boats(base_url, q_limit, q_offset):
    # Create a query against all of your objects of kind "Boat"
    query = datastore_client.query(kind="Boat")
    b_iterator = query.fetch(limit=q_limit, offset=q_offset)
    pages = b_iterator.pages
    results = list(next(pages))
    # If there's more - udpate the offset and next URL
    if b_iterator.next_page_token:
        next_offset = q_offset + q_limit
        next_url = base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
    else:
        next_url = None
    query.order = ["name"]
    # Store the ID and self URL
    for boat in results:
        id = boat.key.id
        boat["id"] = id
        boat["self"] = f"{base_url}/{id}"
    return results, next_url

def get_a_boat(boat_id, url=None):
    # Fetch the boat with the given ID
    key = datastore_client.key('Boat', boat_id)
    target_boat = datastore_client.get(key)
    if target_boat and url:
        target_boat["id"] = target_boat.id
        target_boat["self"] = f"{url}"
    return target_boat
    
def delete_boat(boat_id):
    # Delete the boat
    key = datastore_client.key('Boat', boat_id)
    datastore_client.delete(key)
    # Return
    return 

def load_boat(boat_id, load_id):
    boat = get_a_boat(boat_id)
    if boat:
        # Store the load_id
        load = {"id": load_id}
        boat["loads"].append(load)
        # Save the boat
        datastore_client.put(boat)
        return boat
    return None

        

def unload_boat(boat_id, load_id):
    # Get the boat
    boat = get_a_boat(boat_id)
    if boat:
        # Save the new load for unloading
        new_load = []
        for load in boat["loads"]:
            if load["id"] != load_id:
                new_load.append(load)
        # Update the boat
        boat["loads"] = new_load
        datastore_client.put(boat)
        return boat
    return None    