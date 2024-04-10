#!/usr/bin/env python3
import socket 
import os
import json, base64
import sys
import select
import getpass
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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


# Derive a 256-bit key from K_client
def derive_key(K_client):
    # Convert K_client to bytes
    K_client_bytes = K_client.to_bytes((K_client.bit_length() + 7) // 8, byteorder="big")
    # Derive a key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info = b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(K_client_bytes)

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


def client_program(host, port, user):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # instantiate
    server_add = (host, port)

    try:
        password = getpass.getpass("Please enter your password: ")
        ga_mod_p = generate_ga_mod_p(g, p) #send only ga_mod_p to the server
        W = hash_user_password(password)  # Hash the password to get W

        # Send sign-in message to the server including username, g^a mod p, and the port and ip of the client
        mes = {"type": "SIGN-IN", "username": user,"g^amodp":ga_mod_p, 'port': port, 'ip': host}
        send_message(client_socket, server_add, mes)

        #print("Please enter command:")

        # While online
        while True:
            sockets_list = [sys.stdin, client_socket]
            read_sockets, _, _ = select.select(sockets_list, [], [])  # monitor for read events
            for sock in read_sockets:
                if sock == client_socket:
                    data = sock.recv(65535).decode()  # receive response
                    if data:
                        try:
                            response = json.loads(data)
                            #print(response)  # Proper JSON response
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

                                    #AES requires at least 16 bytes (128 bit) for the key, so we take the first 16 bytes of K_client          
                                    K = derive_key(K_client) 
                                    c_1_bytes = c_1.to_bytes((c_1.bit_length() + 7) // 8, 'big')
                                    # Encrypt c_1 with the derived symmetric key
                                    encrypted_c1 = encrypt_with_key(K, c_1_bytes)
                                    # Client side: converting c_1 to bytes before encryption


                                    # Generate a new nonce 'c_2'
                                    c_2 = random.randint(1, 99999999)

                                    # Prepare and send encrypted c_1 and c_2 to the server
                                    auth_message = {
                                        "type": "AUTH_MESSAGE",
                                        "encrypted_c1": base64.b64encode(encrypted_c1).decode(),  # Include nonce with encrypted message
                                        "c_2": c_2,
                                    }
                                    send_message(client_socket, server_add, auth_message)

                                except Exception as e:
                                    print("Error computing shared key:", e)


                            if response["type"] == "AUTH_RESPONSE":
                                # Decrypt encrypted_c2 received from server
                                encrypted_c2_base64 = response["encrypted_c2"]
                                encrypted_c2 = base64.b64decode(encrypted_c2_base64)
                                
                                try:
                                    decrypted_c2 = decrypt_with_key(K, encrypted_c2)  # K is your derived key
                                    decrypted_c2_int = int.from_bytes(decrypted_c2, byteorder='big')
                                    
                                    # Check if decrypted c_2 matches the one we sent
                                    if decrypted_c2_int == c_2:
                                        print("Log in successful!")
                                    else:
                                        print("Server authentication failed")
                                        
                                except Exception as e:
                                    print("Error during decryption or authentication:", str(e))
                            
                            elif response["type"] == "error":
                                print(response["message"])
                        except json.JSONDecodeError:
                            print("Received malformed data or not in JSON format.")
                    else:
                        print("Received empty response from server.")
  
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