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
# 节点B注册
client_type = "B"
ID_INj = "b2b8d5ed2a4d8b5001ac882322ef4e42"
SKCG_BRC = secrets.token_bytes(16).hex()
IC_j1 = hash_256(SKCG_BRC,ID_INj)
delt_T = 1.0

LL = [client_type, SKCG_BRC]
NodeB.send(pickle.dumps(LL))

ID_CGk = pickle.loads(NodeB.recv(1024))

# 开始认证
GI1, GI2, Mx, TS2 = pickle.loads(NodeB.recv(1024))
startT1 = time.time()

TS2_1 = time.time()
if TS2_1 - TS2 > delt_T:
    raise ValueError("时间过期")

MIDi= xor_strings(GI1,hash_256(IC_j1,str(TS2)))
SK_jk = hash_256(str(TS2),ID_CGk,MIDi,IC_j1)

if GI2 != hash_256(ID_INj,MIDi,str(Mx),SK_jk,str(TS2)):
    raise ValueError("MSG2验证失败")


y = secrets.token_bytes(32).hex()
TS3 = time.time()
My = a_mul_p(int(y,16),P)
NM2 = hash_256(MIDi,ID_INj,ID_CGk,str(Mx),str(My),str(TS3))
NM3 = a_mul_p(int(y,16),ecp.mul(Mx, int(NM2,16), P, int(hash_256(ID_INj),16)))

DIDINj_star = xor_strings(ID_INj,hash_256(MIDi,ID_CGk,str(TS3))[:32])
SK_ji = hash_256(str(NM3),MIDi,ID_INj,str(Mx),str(My))
SKV_ji = hash_256(SK_ji,str(TS3))

test_msg3 = time.time()
MSG3 = [DIDINj_star,NM2,My,SKV_ji,TS3]
NodeB_A.send(pickle.dumps(MSG3))

print("NodeB_section:",(time.time()-startT1)*1000)

# 关闭连接
NodeB.close()
