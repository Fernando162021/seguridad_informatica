import hashlib
import random

def diffie_hellman_mitm():
    # Número primo estándar (RFC3526 1536-bit MODP Group)
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16)
    g = 2

    # Secretos de Alice, Bob y Eve
    sAlice = random.getrandbits(256)
    sBob = random.getrandbits(256)
    sEve = random.getrandbits(256)

    # Alice envía A = g^a mod p, pero Eve intercepta
    A = pow(g, sAlice, p)
    A_eve = pow(g, sEve, p)  # Eve envía esto a Bob en lugar de A

    # Bob envía B = g^b mod p, pero Eve intercepta
    B = pow(g, sBob, p)
    B_eve = pow(g, sEve, p)  # Eve envía esto a Alice en lugar de B

    # Alice calcula la llave compartida con lo que recibió (B_eve)
    K_ae = pow(B_eve, sAlice, p)

    # Bob calcula la llave compartida con lo que recibió (A_eve)
    K_be = pow(A_eve, sBob, p)

    # Eve calcula las llaves compartidas con Alice y Bob
    K_ea = pow(A, sEve, p)  # Clave con Alice
    K_eb = pow(B, sEve, p)  # Clave con Bob

    # Aplicamos hash a las llaves compartidas
    h_ae = hashlib.sha512(int.to_bytes(K_ae, length=1024, byteorder='big')).hexdigest()
    h_be = hashlib.sha512(int.to_bytes(K_be, length=1024, byteorder='big')).hexdigest()
    h_ea = hashlib.sha512(int.to_bytes(K_ea, length=1024, byteorder='big')).hexdigest()
    h_eb = hashlib.sha512(int.to_bytes(K_eb, length=1024, byteorder='big')).hexdigest()

    print(f"Alice y Bob creen que tienen la misma llave: {h_ae == h_be}")
    print(f"Eve tiene acceso a ambas llaves y puede descifrar los mensajes:")
    print(f"Alice - Eve: {h_ae == h_ea}")
    print(f"Bob - Eve: {h_be == h_eb}")
    print(f"  - Hash de la llave de Alice con Eve: {h_ea}")
    print(f"  - Hash de la llave de Bob con Eve: {h_eb}")
