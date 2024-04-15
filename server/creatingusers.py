import json
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64

#THIS FILE IS JUST A SIMULATION OF HOW THE SERVER WOULD STORE USER PASSWORDS IN A DATABASE. IN THE REAL WORLD. YOU WOULD NEVER STORE 
#PASSWORDS IN PLAIN TEXT LIKE THIS ON THE SERVER. 

# Function to generate a safe prime and generator
def generate_dh_parameters():
    # Here, we are using the default parameters, but you can specify others if needed.
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    # Return the parameters p and g
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    return p, g

# Function to compute the verifier g^w mod p for each user
def compute_verifier(g, p, password):
    # Password should be hashed and converted into an integer
    pw_bytes = password.encode('utf-8')
    pw_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    pw_hash.update(pw_bytes)
    w = int.from_bytes(pw_hash.finalize(), byteorder='big')
    
    # Compute g^w mod p
    gw_mod_p = pow(g, w, p)
    return gw_mod_p

# Dictionary of users and their passwords
users_passwords = {
    "alice": "HarryPotter_203",
    "bob": "P3bble_Cur5e",
    "aishu": "Ch*colate101",
    "mallory": "chaRacTer.muLLed0"
}


# Generate your safe prime and generator
p, g = generate_dh_parameters()

# Create a dictionary database for storing users and their verifiers (verifier = g^w mod p where w is the user's password)
database = {
    "p": str(p),
    "g": str(g),
    "users": {}
}

# Compute and store verifiers for each user
for username, password in users_passwords.items():
    verifier = compute_verifier(g, p, password)
    database["users"][username] = {
        "verifier": str(verifier)
    }

# Write the database to a JSON file
with open('users.json', 'w') as config_file:
    json.dump(database, config_file, indent=4)
