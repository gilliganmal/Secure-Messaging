
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
import os

DEFAULT_HASH_ALGO = hashlib.sha1

DEFAULT_BYTEORDER = 'big'

DEFAULT_ENCODING = 'utf-8'

DEFAULT_RADIX = 16

DEFAULT_SALT_SIZE = 32

DEFAULT_SECRETSIZE = 256

gN_1024 = {
    'g': 2,
    'N': int(
        'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
        '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
        '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
        '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
        'FD5138FE8376435B9FC61D2FC0EB06E3', 16
        )
    }

DEFAULT_GROUP_PARAMETERS = gN_1024

def get_randombytes(len):
	'''Generates len length secure random bytes.'''
	return os.urandom(len)

def obj_to_bytes(obj):
	'''Converts object to byte array.'''
	if type(obj) == int:
		return obj.to_bytes((obj.bit_length() + 7)//8, byteorder=DEFAULT_BYTEORDER)
	elif type(obj) == str:
		return bytes(obj, DEFAULT_ENCODING)
	else:
		return None

def compute_hash(*args):
	'''Hashes concatenated argument objects.'''
	algorithm = DEFAULT_HASH_ALGO
	m = algorithm()
	for i in args:
		m.update(i if type(i) == bytes else obj_to_bytes(i))
	return m.digest()

def obj_to_int(obj):
	'''Converts object to integer.'''
	if type(obj) == bytes:
		return int.from_bytes(obj, byteorder=DEFAULT_BYTEORDER)
	elif type(obj) == str:
		return int(obj, DEFAULT_RADIX)
	else:
		return obj

def compute_padding(obj, byte_length):
	r = obj_to_bytes(obj)
	padding = b'\x00'*((byte_length+7)//8 - len(r))
	return padding+r

def compute_M(g, N, I, s, A, B, K):
	'''
	Calculates evidence message.
	'''
	hashed_g = compute_hash(g)
	hashed_N = compute_hash(N)
	hashed_I = compute_hash(I)
	hashed_xor = bytes(map(lambda i: i[0]^i[1], zip(hashed_g, hashed_N)))
	return compute_hash(hashed_xor, hashed_I, s, A, B, K)