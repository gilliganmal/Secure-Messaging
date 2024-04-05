#!/usr/bin/env python3
import socket
import argparse
import json
import getpass

connections = {'username': []} # dictotnary for addresses connected to users
users = [] # list of all users online

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

        # branches based on what type of packet we recived
        if type == 'SIGN-IN':
            store_user(data, address)
        elif type == 'list':
            list_users(server_socket, address)
        elif type == 'send':
            send_message(data, server_socket, address)
        elif type == 'exit':
            user = data['USERNAME']
            users.remove(user)
        else:
            mes = "Please enter a valid command either 'list' or 'send'"
            server_socket.sendto(mes.encode(), address)

# after a user logs in save their data to plaves it can be acessed later
def store_user(data, address):
    users.append(data['username'])
    connections[data['username']] = {'ADDRESS': str(address)}

# lists all users currently online
def list_users(conn, address):
    data = "<- Signed In Users: "
    for item in users:
        data += item
        data += " "
    conn.sendto(data.encode(), address)

# returns the address of the client requested 
def send_message(data, conn, address):
    sendto = data['USERNAME']

    # ensures the person being messaged is online
    if sendto in users:
        to_addr = connections[sendto]['ADDRESS']
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
            print("You have succesfully logged in\n")
            parser = argparse.ArgumentParser(usage="./chat_server <-sp port>")
            parser.add_argument('-sp', type=int, required=False, dest='port')
            args = parser.parse_args()
            
            port = args.port

            js = {
            "host": "127.0.0.1",
            "port": port
            }

            config = json.dumps(js)
            
            with open('server_config.json', 'w') as f:
                f.write(config)

            server_program(port)
        
        else:
            print("Incorrect try again")
            count += 1
    
    print("Too many incorrect attempts exiting...\n")