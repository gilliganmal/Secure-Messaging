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

def generate_p_and_g():
    # Generate parameters for Diffie-Hellman key exchange
    parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())

    # Extract the prime 'p' and generator 'g'
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    return p, g

# Generate a random private key 'b'
def generate_private_key():
    return random.randint(1, 99999999)

# Generate a random nonce 'c1'
def generate_nonce():
    return random.randint(1, 99999999)

# Generate a 32-bit number 'u'
def generate_u():
    return random.randint(0, (1 << 32) - 1)

# Calculate K = g^(b(a+u*W))
def calculate_shared_key(b, a, verifier, u, g, p):
    return pow(a, b + u * verifier, p)

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
    verifier = int(data['verifier'], 16)  # Convert hexadecimal string to integer
    p, g = generate_p_and_g()
    b = generate_private_key()
    u = generate_u()
    c1 = generate_nonce()
    gWmodp = pow(g, verifier, p)  # Calculate g^verifier mod p


    # Calculate the shared key K = g^(b(a+u*verifier))
    K = calculate_shared_key(b, int(data['gamodp']), verifier, u, g, p)


    # Send (g^b + g^W mod p, u, c1) to the client
    # Send (g^b + g^W mod p, u, c1) to the client
    message = {
        'g^b_mod_p': pow(g, b, p),
        'u': u,
        'c1': c1
    }

    # Convert message to JSON format
    message_json = json.dumps(message)

    # Send the JSON message back to the client
    conn.sendto(message_json.encode(), address)


    users[username] = {
        'g_verifier': gWmodp,
        'address': str(address),
        'gamodp': data['gamodp'],
        'K': K
    }


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
