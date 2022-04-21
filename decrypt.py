from generate_keys import modexp
import random
import math
import sys

# Decodes integers to the original message bytes
def decode(cipher, bits):
	bytes_array = []

	'''
	For example
	if "You" were encoded.
	Letter        #ASCII
	Y              89
	o              111
	u              117
	If the encoded integer is 7696217 and k = 3
	m[0] = 7696217 % 256 % 65536 / (2 ^ (8 * 0)) = 89 = 'Y'
	7696217 - (89 * (2 ^ (8 * 0))) = 7696128
	m[1] = 7696128 % 65536 / (2 ^ (8 * 1)) = 111 = 'o'
	7696128 - (111 * (2 ^ (8 * 1))) = 7667712
	m[2] = 7667712 / (2 ^ (8 * 2)) = 117 = 'u'
	'''

	# Each encoded integer is a linear combination of k message bytes
	# k must be the number of bits in the prime divided by 8 because each
	# Message byte is 8 bits long
	k = bits // 8

	for num in cipher:
		# Get the k message bytes from the integer, i counts from 0 to k - 1
		for i in range(k):
			temp = num
			# j goes from i + 1 to k - 1
			for j in range(i + 1, k):
				# Get remainder from dividing integer by 2 ^ (8 * j)
				temp = temp % (2 ** (8 * j))
			# Message byte representing a letter is equal to temp divided by 2^(8*i)
			letter = temp // (2 ** (8 * i))
			bytes_array.append(letter)
			# Subtract the letter multiplied by the power of two from num so so the next message byte can be found
			num = num - (letter * (2 ** (8 * i)))

	plain = bytearray(b for b in bytes_array).decode('utf-16')
	return plain

# Performs decryption on the cipher pairs found in Cipher using Prive key K2 and writes the decrypted values to file Plaintext
def decrypt(key, cipher):
	plaintext = []

	cipherArray = cipher.split()
	if(not len(cipherArray) % 2 == 0):
		return "Malformed Cipher Text"

	for i in range(0, len(cipherArray), 2):
		c = int(cipherArray[i])
		d = int(cipherArray[i + 1])

		# s = c ^ x mod p
		s = modexp(c, key["x"], key["p"])
		# Plaintext integer = d * s ^ -1 mod p
		plain = (d * modexp(s, key["p"]-2, key["p"])) % key["p"]
		# Add plain to list of plaintext integers
		plaintext.append(plain)

	plaintext = decode(plaintext, key["bits"])
	plaintext = "".join([ch for ch in plaintext if ch != '\x00'])

	return plaintext