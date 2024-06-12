import pickle
import socket
import time

from FunctionMod import *

import json

NodeB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
NodeB.connect(server_address)

NodeB_A = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.2', 234)
NodeB_A.connect(server_address)

P = ecp.generator()
# 注册
client_type = "B"
SIDj = secrets.token_bytes(16).hex()

LL = [client_type, SIDj ]
NodeB.send(pickle.dumps(LL))
Skeyj = pickle.loads(NodeB.recv(1024))
delt_T = 1.0
rj = 3983623723 # 1594324474

p= 115792089210356248762697446949407573530086143415290314195533631308867097853951

# 开始认证===========================================================================
Hj, VSNj, SIDj_11, Ei_11, TS2, len1= pickle.loads(NodeB.recv(1024))
start1 = time.time()

if time.time()-TS2>delt_T:
    raise ValueError("T2时间过期")
DIDi = xor_strings(hash_256(SIDj, Skeyj, TS2), SIDj_11)
Ei = xor_strings(Ei_11, hash_256(Skeyj, TS2))
Ag_1 = int(xor_strings(Skeyj[:len1], Hj))

if VSNj != hash_256(Skeyj, SIDj, Ag_1, Hj, TS2):
    raise ValueError("MSG2验证失败")

# rj = secrets.token_bytes(16).hex()
TS3 = time.time()
x2 = hash_256(DIDi,SIDj,Ei)


Nj = T(rj,int(x2[:32],16),p)


SKij = hash_256(T(rj,Ag_1,p)%p,DIDi,TS3)


Pj = hash_256(SKij, Nj, TS3)
len2 = len(hex(Nj)[2:])
Nj_1 = xor_strings(str(Nj), hash_256(DIDi,SIDj,TS3)[:len2])

print("B_section:",(time.time()-start1)*1000)
MSG3 = [Pj,Nj_1,TS3,len2]
NodeB_A.send(pickle.dumps(MSG3))

# 关闭连接
NodeB.close()
