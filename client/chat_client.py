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


# Assume p and g are constants known beforehand (this would be received securely or pre-shared in the real world)
# Correct assignment without a trailing comma
p = 26657706621716543356427660489753514568662248287693517583871421471277927394226182218864396868351146221417642314586344696182785804683203615900459253350532133763424792102545316816104252762334972148348580296625704810361300497179705481131533770686041768384955576685725315981437137175593884768188705226027006595344505706524592489783446723617919991220927789085885301742953663221415782700415596054304650368202029917453579747975511696459512765650159731430161128908423206364785585445059168667792411307712050519651610778186819509309072269879529014542271328260308499119722195522566171386824542462872262334173649010497446756146287
g = 2

# Global variable to hold the client's private key 'a'
client_private_key_a = None

# Function to generate a random private key 'a' and calculate 'g^a mod p'
def generate_ga_mod_p(g, p):
    global client_private_key_a
    client_private_key_a = random.SystemRandom().randint(1, p-1)
    ga_mod_p = pow(g, client_private_key_a, p)
    return ga_mod_p

# Function to hash the password before the client computes the shared key (the server also does the same and this standard will be
# agreed upon by both the client and server)
def hash_user_password(password):
    # Password should be hashed and converted into an integer
    pw_bytes = password.encode('utf-8')
    pw_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    pw_hash.update(pw_bytes)
    W = int.from_bytes(pw_hash.finalize(), byteorder='big')
    return W


# K = g ^(b(a+uW))mod p 
def compute_client_shared_key(B, g, p, a, u, password):
    # Hash the password to get W
    W = hash_user_password(password)
    
    # Compute the exponent (a + uW) mod p
    exponent = (a + u * W) % p
    
    # Compute the shared key K
    K = pow(B, exponent, p)
    
    return K


def client_program(host, port, user):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # instantiate
    server_add = (host, port)

    try:
        password = getpass.getpass("Please enter your password: ")
        ga_mod_p = generate_ga_mod_p(g, p) #send only ga_mod_p to the server
        print(ga_mod_p, "yo dis ga_mod_p")
        W = hash_user_password(password)  # Hash the password to get W

        # Send sign-in message to the server including username, g^a mod p, and the port and ip of the client
        mes = {"type": "SIGN-IN", "username": user,"g^amodp":ga_mod_p, 'port': port, 'ip': host}
        send_message(client_socket, server_add, mes)

        print("Please enter command:")

        # While online
        while True:
            sockets_list = [sys.stdin, client_socket]
            read_sockets, _, _ = select.select(sockets_list, [], [])  # monitor for read events
            for sock in read_sockets:
                if sock == client_socket:
                    data = sock.recv(65535).decode()  # receive response
                    print(data)  # show in terminal remove this later
                    response = json.loads(data)
                    # Inside client_program, after receiving the SRP_RESPONSE message
                    if response["type"] == "SRP_RESPONSE":
                        try:
                            # Parse the server's response
                            B_received = int(response["g^b+g^W_mod_p"])
                            u = int(response["u"])
                            c_1 = int(response["c_1"])
                            a = client_private_key_a

                            # Subtract g^W mod p from B received to get g^b mod p
                            gW_mod_p = pow(g, W, p)
                            B = (B_received - gW_mod_p + p) % p  # Add p to avoid negative result

                            # Now compute the shared key using the received values and the client's private 'a'
                            K_client = compute_client_shared_key(B, g, p, client_private_key_a, u, password)
                            print(K_client, "yo dis client side K")
                        except Exception as e:
                            print("Error computing shared key:", e)
  
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