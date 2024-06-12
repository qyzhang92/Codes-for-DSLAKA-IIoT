import pickle
import socket
import time
import base64
from FunctionMod import *
deltT = 1.0
import json
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
GateWay_address = ('127.0.0.2', 234)
server_socket.bind(GateWay_address)
server_socket.listen(1)
# 等待设备连接
NodeA2B, client_address = server_socket.accept()


NodeB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
NodeB.connect(server_address)

P = ecp.generator()
ki_tmp = ecp.generator()
# 注册
client_type = "B"
SIDj = secrets.token_bytes(16).hex()

LL = [client_type, SIDj ]
NodeB.send(pickle.dumps(LL))
fj = pickle.loads(NodeB.recv(1024))

# 开始认证===========================================================================
MI_i,Zi, Ni,T1 = pickle.loads(NodeA2B.recv(1024))

start1 = time.time()
if time.time()-T1>deltT:
    raise ValueError("T1过期")
T2 = time.time()
Aj = hash_256(fj, Ni, T2)

MSG2 = [MI_i, Ni, SIDj, Aj, T1, T2]
NodeB.send(pickle.dumps(MSG2))

Fij, Hj, Ei, T3 = pickle.loads(NodeB.recv(1024))

if time.time()-T3>deltT:
    raise ValueError("T3过期")
Yi_1 = xor_strings(Fij, hash_256(fj, T3)[:44])
Hj_1 = hash_256(Yi_1)


Ki_str = xor_strings(Zi,Yi_1[:44])
restored_ki_bytes = base64.b64decode(Ki_str)
ki_tmp.fromBytes(restored_ki_bytes)
Ki = ki_tmp

if Hj_1 != Hj:
    raise ValueError("MSG3 校验失败")
T4 = time.time()
b = secrets.token_bytes(32).hex()
KJ = int(b,16)*P
tx = time.time()
KJ_str = base64.b64encode(KJ.toBytes(compress=True)).decode('utf-8')
ty = time.time()


Rij = xor_strings(hash_256(Ki,T4)[:44],KJ_str)
SK = hash_256(int(b,16)*Ki)


print("B_section:",(time.time()-(ty-tx)-start1)*1000)
MSG3 = [Rij, Ei, T4]
NodeA2B.send(pickle.dumps(MSG3))


# 关闭连接
NodeB.close()
