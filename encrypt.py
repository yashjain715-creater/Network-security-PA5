from generate_keys import modexp
import random
import math
import sys

# Encodes bytes to integers mod p.
def encode(plaintext, bits):
	byte_array = bytearray(plaintext, 'utf-16')
	# z is the array of integers mod p
	z = []

	# Each encoded integer will be a linear combination of k message bytes
	# k must be the number of bits in the prime divided by 8 because each
	# message byte is 8 bits long
	k = bits // 8

	# j marks the jth encoded integer
	# j will start at 0 but make it -k because j will be incremented during first iteration
	j = -1 * k

	# num is the summation of the message bytes
	num = 0

	for i in range(len(byte_array)):
		# If i is divisible by k, start a new encoded integer
		if i % k == 0:
			j += k
			num = 0
			z.append(0)

		# Add the byte multiplied by 2 raised to a multiple of 8
		z[j // k] += byte_array[i] * (2 ** (8 * (i % k)))

	# For example,
	# If n = 24, k = n / 8 = 3
	# z[0] = (summation from i = 0 to i = k) m[i] * (2 ^ (8 * i))
	# Where m[i] is the ith message byte
	return z

# Encrypts a string plaintext using the public key k
def encrypt(key, plaintext):
	z = encode(plaintext, key["bits"])

	# Cipher_pairs list will hold pairs (c, d) corresponding to each integer in z
	cipher_pairs = []
	for i in z:
		# Pick random y from (0, p-1) inclusive
		y = random.randint(0, key["p"])
		#c = g ^ y mod p
		c = modexp(key["g"], y, key["p"])
		#d = i * h ^ y mod p
		d = (i * modexp(key["h"], y, key["p"])) % key["p"]
		cipher_pairs.append([c, d])

	cipher_text = ""
	for pair in cipher_pairs:
		cipher_text += str(pair[0]) + " " + str(pair[1]) + " "

	return cipher_text