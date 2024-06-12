import pickle
import socket
import time

from FunctionMod import *

import json

NodeB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
NodeB.connect(server_address)

P = ecp.generator()
# 注册
client_type = "B"
SIDk = secrets.token_bytes(16).hex()

LL = [client_type, SIDk ]
NodeB.send(pickle.dumps(LL))
KGs = pickle.loads(NodeB.recv(1024))

# 开始认证===========================================================================
M2, V2 = pickle.loads(NodeB.recv(1024))
start1 = time.time()

M2_KGs = xor_strings(M2, KGs)
IDi = M2_KGs[:32]
GIDj = M2_KGs[32:64]
R1 = M2_KGs[64:96]
R2 = M2_KGs[96:]


V2_star = hash_256(IDi, GIDj, KGs, R1, R2)
if V2_star!=V2:
    raise ValueError("MSG2验证失败")


R3 = secrets.token_bytes(16).hex()
SK = hash_256(IDi, GIDj, SIDk, R1, R2, R3)
M3 = xor_strings(R3, KGs[:32])
V3 = hash_256(R3,KGs,SK)

print("B_section:",(time.time()-start1)*1000)
MSG3 = [M3, V3]
NodeB.send(pickle.dumps(MSG3))


# 关闭连接
NodeB.close()
