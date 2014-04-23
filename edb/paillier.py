import random

def encrypt(modulus, generator, plaintext):
    noise = random.SystemRandom().randint(0, modulus - 1)
    modsquare = modulus * modulus
    return (pow(generator, plaintext, modsquare) *
            pow(noise, modulus, modsquare)) % modsquare

def decrypt(lmbda, mu, modulus, ciphertext):
    return (((pow(ciphertext, lmbda, modulus*modulus) - 1)
             // modulus) * mu) % modulus
