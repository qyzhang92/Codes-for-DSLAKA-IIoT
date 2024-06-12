from FunctionMod import *


P = ecp.generator()
x = secrets.token_bytes(32).hex()
X = int(x,16)*P
# print(int(a,16)*P)
# print(hash_256(big.modmul(int(hash_256(int(a,16)*P),16),b,r)*P))
# print(hash_256(big.modmul(int(hash_256(int(b,16)*P),16),a,r)*P))

