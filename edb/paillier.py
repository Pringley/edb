import math
from Crypto.Util.number import getPrime
from Crypto.Random import random

def encrypt(modulus, generator, plaintext):
    noise = random.randint(0, modulus - 1)
    modsquare = modulus * modulus
    return (pow(generator, plaintext, modsquare) *
            pow(noise, modulus, modsquare)) % modsquare

def decrypt(lmbda, mu, modulus, ciphertext):
    return (((pow(ciphertext, lmbda, modulus*modulus) - 1)
             // modulus) * mu) % modulus

# Simple LCM
def lcm(x, y):
   if x > y:
       greater = x
   else:
       greater = y

   while(True):
       if((greater % x == 0) and (greater % y == 0)):
           lcm = greater
           break
       greater += 1

   return lcm

#http://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

#http://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def generate_keys(bits = 512):
	p = getPrime(bits)
	q = getPrime(bits)
	n = p*q
	lmbda = (p-1)*(q-1)
	g = n+1
	mu = modinv(((p-1)*(q-1)), n)
	private = [lmbda, mu]
	public = [n, g]
	return private, public

def average(ciphertext, n):
	tally = 1
	for i in range (0, len(ciphertext)):
		tally = tally*ciphertext[i]%(n*n)
	return tally, len(ciphertext)
