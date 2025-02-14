# Practica del algoritmo de intercambio de claves
import hashlib
import random


def algorithm():
    # Numero primo de RFC3526 DE 1536 bits - MODP Group
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16)
    g = 2

    print("\n", f'Numero primo compartido publicamente RFC3625: {p}')
    print("\n", f'Numero base compartido publicamente: {g}')

    # Generamos los numeros secretos de Alice y Bob
    sAlice = random.getrandbits(256)
    sBob = random.getrandbits(256)

    print("\n", f'Numero secreto de Alice: {sAlice}')
    print("\n", f'Numero secreto de Bob: {sBob}')

    # Alice manda mensaje a Bob -> A = g^a mod p

    A = pow(g, sAlice, p)
    print("\n", f'Mensaje de Alice a Bob: {A}')

    # Bob manda mensaje a Alice -> B = g^b mod p
    B = pow(g, sBob, p)
    print("\n", f'Mensaje de Bob a Alice: {B}')

    # Alice calcula la llave secreta compartida -> s1 = B^a mod p
    s1 = pow(B, sAlice, p)
    print("\n", f'Llave compartida S1: {s1}')

    # Alice calcula la llave secreta compartida -> s2 = A^b mod p
    s2 = pow(A, sBob, p)
    print("\n", f'Llave compartida S2: {s2}')

    # Comparamos las llaves secretas
    h1 = hashlib.sha512(int.to_bytes(s1, length=1024, byteorder='big')).hexdigest()
    h2 = hashlib.sha512(int.to_bytes(s1, length=1024, byteorder='big')).hexdigest()

    print("\n" + f'h1: {h1}')
    print("\n" + f'h2: {h2}')

    print("\n", h1 == h2)
