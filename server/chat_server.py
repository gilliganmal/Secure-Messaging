#!/usr/bin/env python3
import socket, argparse, json, getpass, random, base64, os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Dictionary to store user information
users = {}

# Generate a random private key 'b'
def generate_private_key():
    return random.randint(1, 99999999)

# Generate a random nonce 'c1' 
def generate_nonce():
    return random.randint(1, 99999999)

# Generate a 32-bit number 'u'
def generate_u():
    return random.randint(0, (1 << 32) - 1)

# Function to compute g^b and g^W mod p to send back to client
#returns gb_mod_p + gW_mod_p and b 
def compute_server_response(g, p, verifier):
    b = generate_private_key()  # Random b
    gb_mod_p = pow(g, b, p)  # Compute g^b mod p
    gW_mod_p = verifier  # This is g^W mod p, already computed as the verifier
    return (gb_mod_p + gW_mod_p) % p, b

# Function to compute shared key where K = g^{b(a+uW}mod p 
def compute_shared_key(gamodp, b, u, verifier, p):
    # Compute the shared key K
    K_server = pow(gamodp * pow(verifier, u, p), b, p)
    return K_server

# Derive a 256-bit key from K_client
def derive_key(K_server):
    # Convert K_client to bytes
    K_server_bytes = K_server.to_bytes((K_server.bit_length() + 7) // 8, byteorder="big")
    # Derive a key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info = b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(K_server_bytes)

#encrypt with the key
def encrypt_with_key(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # Return nonce concatenated with ciphertext

# Function to decrypt data with AES-GCM
def decrypt_with_key(key, encrypted_data_with_nonce):
    aesgcm = AESGCM(key)
    nonce, ciphertext = encrypted_data_with_nonce[:12], encrypted_data_with_nonce[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


# handles all server operations
def server_program(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # get instance
    server_socket.bind(('127.0.0.1', port))

    print("Server Initialized...")

    while True:
        conn, address = server_socket.recvfrom(65535)  # accept new connection

        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = json.loads(conn.decode())
        print("from connected user: " + str(data))
        type = data['type']

        # branches based on what type of packet we received
        if type == 'SIGN-IN':
            store_user(data, address, server_socket)
        if type == 'AUTH_MESSAGE':
            handle_auth_message(data, address, server_socket)
        elif type == 'list':
            list_users(server_socket, address)
        elif type == 'send':
            send_message(data, server_socket, address)
        elif type == 'exit':
            user = data['USERNAME']
            users.pop(user, None)  # Remove user from the dictionary
        # else:
        #     message = {"type": "error", "message": "Invalid command"}         
        #     server_socket.sendto(json.dumps(message).encode(), address)
            
            


# after a user logs in save their data to places it can be accessed later
def store_user(data, address, conn):
    username = data['username']
    gamodp = data['g^amodp']

    # Load server configuration and user database to get the p,g, and verifier of the user
    with open('users.json', 'r') as f:
        user_db = json.load(f)
    
    p = int(user_db['p'])
    g = int(user_db['g'])
    verifier = int(user_db['users'][username]['verifier'])  # This is g^W mod p

    # Compute server response values
    gb_plus_gW_mod_p, b = compute_server_response(g, p, verifier)
    u = generate_u()
    c_1 = generate_nonce()

    # Send server response to client
    response = {
        "type": "SRP_RESPONSE",
        "g^b+g^W_mod_p": gb_plus_gW_mod_p,
        "u": u,
        "c_1": c_1
    }
    conn.sendto(json.dumps(response).encode(), address)

    #Shared key
    # Compute shared key using gamodp from client, b and u from server, and verifier gWmodp from user's stored data
    K_server = compute_shared_key(gamodp, b, u, verifier, p)

    users[address] = {
        "username": username,
        "K_server": K_server,
        "c1": c_1  # Include c1 here for later verification
    }
    


# handling for AUTH_MESSAGE type where the server received the cnrypted c_1 and c_2 from the client. The server needs to make
# sure the c_1 is correct and then send back the encrypted c_2
def handle_auth_message(data, address, server_socket):
    if address in users:
        K_server = users[address]["K_server"]
        c_1 = users[address]["c1"]
        # Derive AES key from K_server
        derived_key = derive_key(K_server)

        try:
            # Decrypt encrypted_c1
            encrypted_c1 = base64.b64decode(data['encrypted_c1'])
            decrypted_c1 = decrypt_with_key(derived_key, encrypted_c1)
            # Convert decrypted_c1 from bytes to an integer
            decrypted_c1_int = int.from_bytes(decrypted_c1, byteorder='big')
            # Verify c_1 or perform necessary checks
            if c_1 != decrypted_c1_int:
                message = {"type": "error", "message": "User verification failed"}         
                server_socket.sendto(json.dumps(message).encode(), address)

            else:
                # Encrypt c_2 received from the client to send back
                c_2 = data['c_2']
                # convert
                c_2_bytes = c_2.to_bytes((c_2.bit_length() + 7) // 8, 'big')
                # Encrypt c_1 with the derived symmetric key
                encrypted_c2 = encrypt_with_key(derived_key, c_2_bytes)
                print(encrypted_c2, "encrypted_c2")
                response = {
                    "type": "AUTH_RESPONSE",
                    "encrypted_c2": base64.b64encode(encrypted_c2).decode(),
                }
                server_socket.sendto(json.dumps(response).encode(), address)
        except InvalidTag:
            message = {"type": "error", "message": "User verification failed"}         
            server_socket.sendto(json.dumps(message).encode(), address)
        

# lists all users currently online
def list_users(conn, address):
    user_list = ", ".join(users.keys())
    data = f"<- Signed In Users: {user_list}"
    conn.sendto(data.encode(), address)

# returns the address of the client requested 
def send_message(data, conn, address):
    sendto = data['USERNAME']

    # ensures the person being messaged is online
    if sendto in users:
        to_addr = users[sendto]['address']
        message = {'ADDRESS': to_addr}
        conn.sendto(json.dumps(message).encode(), address)
    else:
        message = {'ADDRESS': 'fail', 'MES': "<- The Person who you are trying to message is not online"}
        conn.sendto(json.dumps(message).encode(), address)

if __name__ == '__main__':
    count = 0
    while count < 3:
        check = getpass.getpass("Enter Password: ")
        if check == "admin":
            print("You have successfully logged in as admin\n")
            parser = argparse.ArgumentParser(usage="./chat_server <-sp port>")
            parser.add_argument('-sp', type=int, required=False, dest='port')
            args = parser.parse_args()

            port = args.port

            js = {
                "host": "127.0.0.1",
                "port": port
            }

            config = json.dumps(js)

            with open('../server_config.json', 'w') as f:
                f.write(config)

            server_program(port)

        else:
            print("Incorrect try again")
            count += 1

    print("Too many incorrect attempts exiting...\n")