#!/usr/bin/env python3
import socket 
import json
import sys
import select
import getpass
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

list_mes = {'type': 'list'}

# Function to send messages
def send_message(client_socket, server_address, message):
    client_socket.sendto(json.dumps(message).encode(), server_address)

# Function to generate a random salt
def generate_salt():
    return str(random.randint(0, 99999999)).encode()

# Function to generate a random private key 'a'
def generate_private_key():
    return random.randint(1, 99999999)

def generate_p_and_g():
    # Generate parameters for Diffie-Hellman key exchange
    parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())

    # Extract the prime 'p' and generator 'g'
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    return p, g

# Function to generate the verifier based on the password and salt
def generate_verifier(password, salt):
    password_bytes = password.encode()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password_bytes + salt)
    return digest.finalize().hex()

def client_program(host, port, user):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # instantiate
    server_add = (host, port)

    try:
        password = getpass.getpass("Please enter your password: ")

        # Generate a random salt and verifier based on the password
        salt = generate_salt()
        verifier = generate_verifier(password, salt)
        private_key = generate_private_key()
        p, g = generate_p_and_g()
        public_key = pow(g, private_key, p)

        # Send sign-in message to the server including username, salt, and verifier
        mes = {"type": "SIGN-IN", "username": user, "verifier": verifier, "A": public_key, 'port': port, 'ip': host}
        send_message(client_socket, server_add, mes)

        print("Please enter command:")

        # While online
        while True:
            sockets_list = [sys.stdin, client_socket]
            read_sockets, _, _ = select.select(sockets_list, [], [])  # monitor for read events
            for sock in read_sockets:
                if sock == client_socket:
                    data = sock.recv(65535).decode()  # receive response
                    print(data)  # show in terminal
                elif sock == sys.stdin:
                    message = input("")  # take input
                    cmd = message.split()  # split input
                    try:
                        if cmd[0] == 'list':
                            send_message(client_socket, server_add, list_mes)  # send message
                            data = client_socket.recv(65535).decode()  # receive response
                            print(data)  # show in terminal
                        elif cmd[0] == 'send':
                            to = cmd[1]
                            text = get_message(cmd)
                            server_mes = {'type': 'send', 'USERNAME': to}
                            send_message(client_socket, server_add, server_mes)
                            data = client_socket.recv(65535).decode()  # receive ip and port from server

                            load = json.loads(data)
                            if load['ADDRESS'] == 'fail':
                                print(load['MES'])
                            else:
                                addr = eval(load['ADDRESS'])
                                send_mes = "<- <From %s:%s:%s>: %s" % (addr, port, user, text)
                                client_socket.sendto(send_mes.encode(), addr)  # send to other client
                        else:
                            print("<- Please enter a valid command either 'list' or 'send'")
                            data = client_socket.recv(65535).decode()  # receive response
                            print(data)  # show in terminal
                    except IndexError:
                        print("<- Please enter a valid command either 'list' or 'send'")

            sys.stdout.flush()  # flush the buffer to ensure immediate display

    except KeyboardInterrupt:
        exit_mes = {'type': 'exit', 'USERNAME': user}
        send_message(client_socket, server_add, exit_mes)
        print("\nExiting the client.")

def get_message(cmd):
    mes = ''
    length = len(cmd)
    start = 2
    while start < length:
        mes += cmd[start]
        mes += " "
        start = start + 1
    return mes

if __name__ == '__main__':
    with open('../server_config.json', 'r') as f:
        config_data = json.load(f)
        host = config_data['host']
        port = int(config_data['port'])
    
    user = input("Please enter your username: ")

    client_program(host, port, user)
