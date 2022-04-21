from generate_keys import generate_keys
from encrypt import encrypt
from decrypt import decrypt
import random
import math
import sys

def main():
	keys = generate_keys()
	priv = keys["privateKey"]
	pub = keys["publicKey"]
	f = open("message.txt", "r")
	message = f.read()
	print("Original PlainText: ", message)
	cipher = encrypt(pub, message)
	plain = decrypt(priv, cipher)
	print("Decrypted PlainText: ", plain)

	if message == plain:
		print("El Gamal Encryption Worked!")
	else:
		print("There is some problem!")


if __name__ == '__main__':
	main()