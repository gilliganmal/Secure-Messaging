#!/usr/bin/env python3
import socket
import argparse
import json
import getpass
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

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
        elif type == 'list':
            list_users(server_socket, address)
        elif type == 'send':
            send_message(data, server_socket, address)
        elif type == 'exit':
            user = data['USERNAME']
            users.pop(user, None)  # Remove user from the dictionary
        else:
            mes = "Please enter a valid command either 'list' or 'send'"
            server_socket.sendto(mes.encode(), address)


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
        "b": b,
        "u": u,
        "c_1": c_1
    }
    conn.sendto(json.dumps(response).encode(), address)


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
            print("You have successfully logged in\n")
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