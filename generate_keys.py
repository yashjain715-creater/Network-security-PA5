from Crypto.Util.number import getPrime
import random
import math
import sys

def modexp(x, y, p) :
    res = 1   
    x = x % p
   
    if (x == 0):
        return 0
 
    while (y > 0):
        if ((y & 1) == 1) :
            res = (res * x) % p
 
        y = y >> 1 
        x = (x * x) % p
    return res

def find_primitive_root( p ):
	if p == 2:
		return 1

	# The prime divisors of p - 1 are 2 and (p - 1) / 2 because p = 2x + 1 where x is a prime
	p1 = 2
	p2 = (p - 1) // p1

	# Test random g's until one is found that is a primitive root mod p
	while(True):
		g = random.randint(2, p - 1)
		# g is a primitive root if for all prime factors of p - 1, p[i]
		# g ^ ((p - 1) / p[i])(mod p) is not congruent to 1
		if not (modexp(g, (p - 1) // p1, p) == 1):
			if not modexp(g, (p - 1) // p2, p) == 1:
				return g

def generate_keys(bits = 256):
	# p is the prime
	# g is the primitve root
	# x is random in (0, p - 1) inclusive
	# h = g ^ x mod p

	# Get the 256 bit prime using crypto library
	p = getPrime(bits)
	g = find_primitive_root(p)
	g = modexp(g, 2, p)
	x = random.randint(1, (p - 1) // 2)
	h = modexp(g, x, p)

	publicKey = {"p": p, "g": g, "h": h, "bits": bits}
	privateKey = {"p": p, "g": g, "x": x, "bits": bits}

	return {'privateKey': privateKey, 'publicKey': publicKey}
