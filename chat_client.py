#!/usr/bin/env python3
import argparse
import socket 
import json
import sys
import select

list_mes = {'type': 'list'}

# function to send messages
def send_message(client_socket, server_address, message):
    client_socket.sendto(json.dumps(message).encode(), server_address)

# Handles everything client side
def client_program():

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # instantiate
    server_add = (host, port)
    
    try:
        # sends sign in message to the server so they can save user info
        mes = {"type": "SIGN-IN", "username": user, 'port': port, 'ip': host}
        send_message(client_socket, server_add, mes)

        print("Please enter command:")  

        # while online
        while True:
            
            sockets_list = [sys.stdin, client_socket]
            read_sockets, _, _ = select.select(sockets_list, [], [])  # monitor for read events
            for sock in read_sockets:
                # if we message ourselves
                if sock == client_socket:
                    data = sock.recv(65535).decode()  # receive response
                    print(data)  # show in terminal
                elif sock == sys.stdin:
                    message = input("") # take input
                    cmd = message.split()  # split input
                    # handle accidental enter before typing
                    try:
                        # list command
                        if cmd[0] == 'list':
                            send_message(client_socket, server_add, list_mes)  # send message
                            data = client_socket.recv(65535).decode()  # receive response
                            print(data)  # show in terminal
                        # send command
                        elif cmd[0] == 'send':
                            # first we send a request to the server for the address of the person
                            # we want to message
                            to = cmd[1]
                            text = get_message(cmd)
                            server_mes = {'type': 'send', 'USERNAME': to}
                            send_message(client_socket, server_add, server_mes)
                            data = client_socket.recv(65535).decode()  # receive ip and port fromm server

                            # Now send our message directly to the client wanted
                            load = json.loads(data)
                            if load['ADDRESS'] == 'fail':
                                print(load['MES'])
                            else:
                                addr = eval(load['ADDRESS'])
                                send_mes = "<- <From %s:%s:%s>: %s" % (addr, port, user, text)
                                client_socket.sendto(send_mes.encode(), addr) # send to other client
                        else:
                            # prints messages we recive
                            print("<- Please enter a valid command either 'list' or 'send'")
                            data = client_socket.recv(65535).decode()  # receive response
                            print(data)  # show in terminal
                    except IndexError:
                        print("<- Please enter a valid command either 'list' or 'send'")
                    
            sys.stdout.flush()  # flush the buffer to ensure immediate display
    
    except KeyboardInterrupt:
        # tells server we logged out
        exit_mes = {'type': 'exit', 'USERNAME': user}
        send_message(client_socket, server_add, exit_mes)
        print("\nExiting the client.")

# isolates the message to be sent no matter the length
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
    # parses command line
    parser = argparse.ArgumentParser(usage="./chat_client <-u username> <-sip server-ip> <-sp port>")
    parser.add_argument('-u', type=str, required=True, dest='username')
    parser.add_argument('-sip', type=str, required=True, dest='server')
    parser.add_argument('-sp', type=int, required=True, dest='port')
    args = parser.parse_args()
    
    # saves data we'll need to refernce later
    port = args.port
    host = args.server
    user = args.username

    client_program()
