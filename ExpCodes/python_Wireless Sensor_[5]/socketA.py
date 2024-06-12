import hashlib
import json
import pickle
import socket
import time

from FunctionMod import *

P = ecp.generator()
Kj = ecp.generator()
# socke配置  连接服务器
NodeA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
NodeA.connect(server_address)

NodeA2B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.2', 234)
NodeA2B.connect(server_address)


# 获取注册信息
IDi = secrets.token_bytes(16).hex()
PWi = secrets.token_bytes(16).hex()
ri = secrets.token_bytes(16).hex()
delt_T = 1.0
MPi = hash_256(ri, PWi)

# 初始化阶段 注册阶段
client_type = "A"
LL = [client_type, IDi, MPi]
NodeA.send(pickle.dumps(LL))

MI_i, ei = pickle.loads(NodeA.recv(1024))

# 开始认证通知
SIDj = pickle.loads(NodeA.recv(1024))

# 开始认证 =========================================================================================================
start_time = time.time()

MPi_star = hash_256(ri, PWi)
fi = xor_strings(ei, MPi)
T1 = time.time()
Yi = hash_256(fi, T1)[:44]
a = secrets.token_bytes(32).hex()
Ki = int(a,16)*P

import base64

ki_str = base64.b64encode(Ki.toBytes(compress=True)).decode('utf-8')


Zi = xor_strings(ki_str, Yi)
Ni = hash_256(Yi, MI_i, SIDj)

section1 = time.time()-start_time

MSG1 = [MI_i,Zi, Ni,T1]
NodeA2B.send(pickle.dumps(MSG1))

Rij, Ei, T4 = pickle.loads(NodeA2B.recv(1024))
start2 = time.time()

Ei_1 = hash_256(fi, Ni)
if Ei_1 != Ei:
    raise ValueError("MSG4验证失败")

KJ_str = xor_strings(Rij,hash_256(Ki,T4)[:44])
restored_ki_bytes = base64.b64decode(KJ_str)
Kj.fromBytes(restored_ki_bytes)


SK = hash_256(int(a,16)*Kj)

end_time = time.time()

print("A_section:",(time.time()-start2+section1)*1000)
print("All time:",(end_time-start_time)*1000)

# 关闭连接
NodeA.close()
