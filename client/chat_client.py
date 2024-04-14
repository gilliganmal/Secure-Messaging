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


# Assume p and g are constants known beforehand (this would be received securely pre-shared and stored in the real world)
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


# Derive a 256-bit key K_client
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

# Function to handle 'send' command
def handle_send_command(to_username, K, client_socket, server_address):
    nonce_1 = random.randint(1, 99999999)  # Generate a random nonce
    global last_sent_nonce_1  # since we are using this variable outside this function
    last_sent_nonce_1 = nonce_1  # Store the last sent nonce for verification
    # Create the message dictionary
    message_dict = {
        'from': user,
        'to': to_username,
        'nonce_1': nonce_1
    }
    # Convert dictionary to JSON and encode to bytes
    message_bytes = json.dumps(message_dict).encode('utf-8')
    # Encrypt the message with the shared key
    encrypted_message = encrypt_with_key(K, message_bytes)
    # Create a message envelope
    send_message_dict = {
        'type': 'SEND',
        'data': base64.b64encode(encrypted_message).decode('utf-8')  # Encode encrypted data to base64 for transmission
    }
    # Send the encrypted message to the server
    send_message(client_socket, server_address, send_message_dict)

K = None #global variable to hold the derived shared key with server
def client_program(host, port, user):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # instantiate
    server_add = (host, port)
    login = False

    try:
        password = getpass.getpass("Please enter your password: ")
        ga_mod_p = generate_ga_mod_p(g, p) #send only ga_mod_p to the server
        W = hash_user_password(password)  # Hash the password to get W

        # Send sign-in message to the server including username, g^a mod p, and the port and ip of the client
        mes = {"type": "SIGN-IN", "username": user,"g^amodp":ga_mod_p, 'port': port, 'ip': host}
        send_message(client_socket, server_add, mes)


        # While online
        while True:
            sockets_list = [sys.stdin, client_socket]
            read_sockets, _, _ = select.select(sockets_list, [], [], 12)  # monitor for read events with timeout
            if not read_sockets:
                print("No data received from the server. Exiting.")
                exit_message = {'type': 'exit', 'USERNAME': user}
                send_message(client_socket, server_add, exit_message)
                client_socket.close()
                sys.exit(0)

            for sock in read_sockets:
                if sock == client_socket:
                    data = sock.recv(65535).decode()  # receive response
                    if data:
                        response = json.loads(data)
                        # Inside client_program, after receiving the SRP_RESPONSE message
                        #print("response here " + str(response))
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
                                # Client side: converting c_1 to bytes before encryption
                                c_1_bytes = c_1.to_bytes((c_1.bit_length() + 7) // 8, 'big')
                                # Encrypt c_1 with the derived symmetric key
                                encrypted_c1 = encrypt_with_key(K, c_1_bytes)

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
                                    login = True
                                    print("Log in successful!\nPlease enter command: ", end=' ', flush=True)
                                else:
                                    print("Server authentication failed")
                            except Exception as e:
                                print("Error decrypting c_2:", e)
                        elif response["type"] == "error":
                            print(response["message"])
                            if(response["login"]) == "yes":
                                    user = input("Please enter your username: ")
                                    client_program(host, port, user)
                            else:
                                exit(0)
                        elif response["type"] == "user_offline":
                            # Decrypt the message from the server
                            encrypted_data = base64.b64decode(response["message"])
                            decrypted_data = decrypt_with_key(K, encrypted_data)
                            print("\n<- " + decrypted_data.decode('utf-8'), "\nPlease enter command: ", end=' ', flush=True)

                        elif response["type"] == "server_send":
                            try:
                                encrypted_data_A = base64.b64decode(response["data"])
                                decrypted_data_A_bytes = decrypt_with_key(K, encrypted_data_A)
                                print("1")
                                decrypted_data_A_str = decrypted_data_A_bytes.decode('utf-8')
                                decrypted_data_A = json.loads(decrypted_data_A_str)


                                recipient_address = decrypted_data_A["to_address"]
                                shared_key_AB = decrypted_data_A["shared_key"]
                                shared_key = derive_key(shared_key_AB)
                                print(shared_key, "shared key")

                                verify_nonce_1 = decrypted_data_A["nonce_1"]
                                if verify_nonce_1 != last_sent_nonce_1:
                                    print("Nonce verification failed. Server cannot be trusted.")
                                    sys.exit(0)
                                data_to_be_sent_to_recipient = decrypted_data_A["ticket_to_B"]


                                # Convert recipient_address from list to tuple and use it
                                if recipient_address:
                                    recipient_tuple = (recipient_address[0], int(recipient_address[1]))  # Convert list to tuple and ensure port is an integer

                                    nonce_2 = random.randint(1, 99999999)
                                    global last_nonce_2
                                    last_nonce_2 = nonce_2
                                    nonce_2_bytes = nonce_2.to_bytes((nonce_2.bit_length() + 7) // 8, 'big')
                                    encrypted_nonce_2 = encrypt_with_key(shared_key, nonce_2_bytes)
                                    whole_response = { "type": "shared_key",
                                                      "from_user": user,
                                                      "recipient_data": data_to_be_sent_to_recipient,
                                                      "nonce_2": base64.b64encode(encrypted_nonce_2).decode()
                                    }
                                    print(nonce_2, "nonce 2 sent by client A")
                                    client_socket.sendto(json.dumps(whole_response).encode(), recipient_tuple)
                                else:
                                    print("Invalid recipient address")

                            except Exception as e:
                                print(f"Failed to process server_send data: {e}")
                        elif response["type"] == "shared_key":
                            #user_communications = {}
                            #ADD A TRY CATCH HERE
                            encrypted_data = base64.b64decode(response["recipient_data"])
                            decrypted_data_bytes = decrypt_with_key(K, encrypted_data)
                            decrypted_data_B_str = decrypted_data_bytes.decode('utf-8')  # Convert bytes to string
                            decrypted_data = json.loads(decrypted_data_B_str)  # Parse string to JSON
                            shared_key_with_sender = decrypted_data["shared_key"]
                            shared_key = derive_key(shared_key_with_sender)
                            from_user = decrypted_data["from_user"]
                            #user_communications
                            encrypted_nonce_2 = base64.b64decode(response["nonce_2"])
                            decrypted_nonce_2_bytes = decrypt_with_key(shared_key, encrypted_nonce_2)
                            decrypted_nonce_2 = int.from_bytes(decrypted_nonce_2_bytes, byteorder='big')  # Parse string to JSON
                            print(decrypted_nonce_2, "decrypted nonce 2")

                            nonce_2minus1 = decrypted_nonce_2 - 1
                            nonce_2minus1_bytes = nonce_2minus1.to_bytes((nonce_2minus1.bit_length() + 7) // 8, 'big')
                            nonce_3 = random.randint(1, 99999999)
                            print(nonce_3, "nonce 3 from client B")
                            nonce_3_bytes = nonce_3.to_bytes((nonce_3.bit_length() + 7) // 8, 'big')
                            nonce = {
                                "nonce_2minus1": nonce_2minus1_bytes,
                                "nonce_3": nonce_3_bytes
                            }
                            encrypted_nonces = encrypt_with_key(shared_key, nonce)
                            message = {
                                "type": "nonce_check_1",
                                "nonces" : base64.b64encode(encrypted_nonces).decode()
                            }
                            client_socket.sendto(json.dumps(message).encode(), )
                        # elif response["type"] == "nonce_check_1":
                        #     encrypted_nonces = base64.b64decode(response['nonces'])
                        #     #decrypt_nonces = decrypt_key() decrypt the encrypted nonces with the shared key .. add a dictionary storage containing users and their shared keys with them
                        #     #check to see that received n2 - 1 is actually the n2 nonce that you sent - 1
                        #     #send back n3 - 1 to complete mutual authentication
                        #     message = {
                        #         #"type": "nonce_check_2"
                        #         #"nonce_3minus1" : 
                        #     }
                        #     #send to the the sender
                        # elif response["type"] == "nonce_check_2":
                        #     #user_communications
                        #     encrypted_nonce_3minus1 = base64.b64decode(response["nonce_3minus1"])
                        #     decrypted_nonce_3minus1_bytes = decrypt_with_key(shared_key, encrypted_nonce_3minus1)
                        #     decrypted_nonce3minus1= int.from_bytes(decrypted_nonce_3minus1_bytes, byteorder='big')  # Parse string to JSON
                        #     # if decrypted_nonce3minus1 is actually the nonce3 that you sent minus 1, print out a message saying mutual authentication successful
                        #     # then actually send the original message to the recipient encrypted using the shared key and all future messages as well


                        if response["type"] == "GOODBYE":
                            print("\n" + response["message"])
                            print("\nExiting the client.")    
                            exit(0)                                 

            # After receiving data or handling input
            if login and (sock == sys.stdin):
                message = input().strip()
                if message:
                    cmd = message.split()
                    if cmd[0] == 'list':
                        send_message(client_socket, server_add, list_mes)  # send message
                        data = client_socket.recv(65535).decode()  # receive response
                        print("\n" + data, "\nPlease enter command: ", end='', flush=True)  # show in terminal
                    elif cmd[0] == 'send' and len(cmd) >= 3:
                        # Extract the username to send to and the message text
                        to_username = cmd[1]
                        # Call the new function to handle the send command
                        handle_send_command(to_username, K, client_socket, server_add)
                    elif cmd[0] == 'exit':
                        exit_message = {'type': 'exit', 'USERNAME': user}
                        send_message(client_socket, server_add, exit_message)
                        print("\nExiting the client.")
                        client_socket.close()  # Close the socket
                        sys.exit(0)  # Exit the program
                    else:
                        print("<- Please enter a valid command either 'list' or 'send'")
                        data = client_socket.recv(65535).decode()  # receive response
                        print(data)  # show in terminal
                sys.stdout.flush()  # flush the buffer to ensure immediate display

    except KeyboardInterrupt:
        exit_message = {'type': 'exit', 'USERNAME': user}
        send_message(client_socket, server_add, exit_message)
        print("\nExiting the client.")
        sys.exit(0)  # Ensure the client exits after sending the message


# gets the whole message as opposed to one word
# IDK IF WE STILL NEED THIS
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