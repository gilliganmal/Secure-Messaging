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
p = 24525119142461202313734537873080049929886105316630406614317876427891268833809737277896173418296624901059130314283519470592394506952609592023180515949773374460853938635866861846159740201266737768591969398045107673047426148684891326393414592149730384425649054250704315168537782545884533483467953326944661437151019497093610850753241601039505225954098161032625562429473094228330878228613111557555892864006586870587587009838820565955970875629552386568500191753071049110794496764616747949817076222602272431826159871686909422579136502812773437429593166767616598335611472785726783829016914851411107953472066707494191022352407
g = 2

# Function to generate a random private key 'a' and calculate 'g^a mod p'
def generate_ga_mod_p(g, p):
    a = random.SystemRandom().randint(1, p-1)  # Private key 'a'
    ga_mod_p = pow(g, a, p)  # Public value 'g^a mod p'
    return ga_mod_p, a  # Return both for later use

def client_program(host, port, user):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # instantiate
    server_add = (host, port)

    try:
        password = getpass.getpass("Please enter your password: ")
        ga_mod_p, _ = generate_ga_mod_p(g, p) #send only ga_mod_p to the server


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