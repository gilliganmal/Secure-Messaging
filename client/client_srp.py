from utils import *

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

