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
from utils import *

list_mes = {'type': 'list'}

class ClientSRP:
	"SRP client-side class."
	def __init__(self, gn=DEFAULT_GROUP_PARAMETERS):
		self.username = ''
		self.password = ''
		self.g = gn['g']
		self.N = gn['N']
		self.a = 0
		self.A = 0
		self.M = b''
		self.hashed_AMK = b''
		self.session_key = b''
		self.auth = False
	
	def _compute_x(self, salt, username, password):
		'''
		Computes x according to the RFC formula:
		x = SHA1(s | SHA1(I | ":" | P))
		'''
		separator = b':'
		h_up = compute_hash(username, separator, password)
		x = compute_hash(salt, h_up)
		return int.from_bytes(x, byteorder=DEFAULT_BYTEORDER)

	def compute_verifier(self, username, password, gn=DEFAULT_GROUP_PARAMETERS, byte_size=DEFAULT_SALT_SIZE):
		'''
		Creates the SRP verifier according to the RFC formula:
		x = SHA1(s | SHA1(I | ":" | P))
        v = g^x % N
		'''
		self.username = username
		self.password = password
		salt = get_randombytes(byte_size)
		x = self._compute_x(salt, username, password)
		verifier = pow(self.g, x, self.N)
		return salt, verifier

	def compute_client_values(self, byte_size=DEFAULT_SECRETSIZE):
		'''
		Computes client's private and public values:
		a = random()
		A = g^a % N  
		'''
		self.a = obj_to_int(get_randombytes(byte_size))
		self.A = pow(self.g, self.a, self.N)
		return self.A
	
	def compute_premaster_secret(self, salt, server_B):
		'''
		Calculates client premaster secret
        u = SHA1(PAD(A) | PAD(B))
        k = SHA1(N | PAD(g))
        x = SHA1(s | SHA1(I | ":" | P))
        <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
		'''
		server_B = obj_to_int(server_B)
		l = self.N.bit_length()

		padded_client_A = compute_padding(self.A, l)
		padded_server_B = compute_padding(server_B, l)

		u = obj_to_int(compute_hash(padded_client_A, padded_server_B))
		x = self._compute_x(salt, self.username, self.password)

		padded_g = compute_padding(self.g, l)
		k = obj_to_int(compute_hash(self.N, padded_g))

		t1 = server_B - k * pow(self.g, x, self.N)
		t2 = self.a + u * x
		self.premaster_secret = pow(t1, t2, self.N)
		return self.premaster_secret
	
	def compute_session_key(self, salt, server_B):
		'''
		Calculates client's session key and evidence message.
		M = H(H(N) XOR H(g) | H(U) | s | A | B | K)
		H(A | M | K)
		'''
		self.session_key = compute_hash(self.premaster_secret)
		self.M = compute_M(self.g, self.N, self.username, salt, self.A, server_B, self.session_key)
		self.hashed_AMK = compute_hash(self.A, self.M, self.session_key)
		return self.M
	
	def verify_session(self, server_hashed_AMK):
		if self.hashed_AMK == server_hashed_AMK:
			self.auth = True
		return self.hashed_AMK

	@property
	def authenticated(self):
		return self.auth


'''
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
        mes = {"type": "SIGN-IN", "username": user, "verifier": verifier, "gamodp": public_key, 'port': port, 'ip': host}
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
'''