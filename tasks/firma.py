import hashlib
import Crypto.Random
import Crypto.Util.number

# Numero 4 de Fernet
e = 65537

# Calculamos la llave publica de Alice
pA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)

nA = pA * qA
print(f'\n RSA llave publica nAlice: {nA}')

# Calculamos la llave publica de Bob
pB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)

nB = pB * qB
print(f'\n RSA llave publica nAlice: {nB}')

# Calcular la llave privada de Alice
phiA = (pA - 1) * (qA - 1)
dA = Crypto.Util.number.inverse(e, phiA)

print(f'\n RSA llave privada Alice dA: {dA}')
# Calcular la llave privada de Bob
phiB = (pB - 1) * (qB - 1)
dB = Crypto.Util.number.inverse(e, phiB)

print(f'\n RSA llave privada Bob dB: {dB}')
# Firmamos el mensaje
mensaje = "hola mundo"
print(f'\n Mensaje: {mensaje}')

# Generamos el hash del mensaje
hM = int.from_bytes(hashlib.sha256(mensaje.encode('utf-8')).digest(), byteorder='big')
print(f'\n HASH de hM: {hex(hM)}')

# Firmamos el Hash usando la llave privada de Alice y se lo enviamos a Bob
sA = pow(hM, dA, nA)
print(f'\n Firma: {sA}')

# Bob verifica la firma de Alice
hM1 = pow(sA, e, nA)
print(f'HASH DE hM1 {hex(hM1)}')

# Verificamos
print(f'{hM==hM1}')