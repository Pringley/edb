import math
import collections

from Crypto.Util.number import getPrime
from Crypto.Random import random

def encrypt(key, plaintext):
    noise = random.randint(0, key.modulus - 1)
    modsquare = key.modulus * key.modulus
    return (pow(key.generator, plaintext, modsquare) *
            pow(noise, key.modulus, modsquare)) % modsquare

def decrypt(key, ciphertext):
    return (((pow(ciphertext, key.lambda_, key.modulus*key.modulus) - 1)
             // key.modulus) * key.mu) % key.modulus

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

PublicKey = collections.namedtuple('PublicKey', ('modulus', 'generator'))
Key = collections.namedtuple('_Key', ('modulus', 'generator', 'lambda_', 'mu'))
Key.public = lambda self: PublicKey(self.modulus, self.generator)

def generate_keys(bits=512):
	p = getPrime(bits//2)
	q = getPrime(bits//2)
	n = p*q
	lmbda = (p-1)*(q-1)
	g = n+1
	mu = modinv(((p-1)*(q-1)), n)
	return Key(n, g, lmbda, mu)

def exp(base, exponent, modulus):
    if exponent == 0:
        return 1
    elif exponent == 1:
        return base
    elif exponent%2 == 0:
        return exp((base*base)%modulus, exponent/2, modulus)
    else:
        return base*exp((base*base)%modulus, (exponent-1)/2, modulus)%modulus

def average(key, ciphertext):
    n = key.modulus
    tally = 1
    for i in range (0, len(ciphertext)):
        tally = tally*ciphertext[i]%(n*n)
    k = random.randint(1, int(math.sqrt(n)-1))
    tally = exp(tally, k, n*n)
    return tally, len(ciphertext)*k
