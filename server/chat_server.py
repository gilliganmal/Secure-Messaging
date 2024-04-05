#!/usr/bin/env python3
import socket
import argparse
import json
import getpass
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
            store_user(data, address)
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
def store_user(data, address):
    username = data['username']
    verifier = int(data['verifier'], 16)  # Convert hexadecimal string to integer
    p, g = generate_p_and_g()
    g_verifier = pow(g, verifier, p)  # Calculate g^verifier mod p

    # Store user information in the dictionary
    users[username] = {
        'g_verifier': g_verifier,
        'address': str(address),
        'public_key': data['A']
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
