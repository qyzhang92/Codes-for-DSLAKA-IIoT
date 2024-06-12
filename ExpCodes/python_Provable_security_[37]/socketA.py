import hashlib
import json
import pickle
import socket
import time

from FunctionMod import *


P = ecp.generator()
# socke配置  连接服务器
NodeA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
NodeA.connect(server_address)


# 获取注册信息


IDi = secrets.token_bytes(16).hex()
PWi = secrets.token_bytes(16).hex()
a = secrets.token_bytes(16).hex()
delt_T = 1.0
HPWi = hash_256(PWi,a)

# 初始化阶段 注册阶段
client_type = "A"
LL = [client_type, IDi, HPWi]
NodeA.send(pickle.dumps(LL))

A1, TEMP, X = pickle.loads(NodeA.recv(1024))

A2 = xor_strings(a, hash_256(IDi,PWi)[:32])
A3 = hash_256(IDi, HPWi)

# 开始认证通知
SIDk = pickle.loads(NodeA.recv(1024))

# 开始认证 =========================================================================================================
start_time = time.time()

a_star = xor_strings(A2, hash_256(IDi, PWi)[:32])

HPWi_star = hash_256(PWi, a_star)
A3_star = hash_256(IDi, HPWi_star)
if A3!=A3_star:
    raise ValueError("本地验证失败")


w = secrets.token_bytes(32).hex()
R1 = secrets.token_bytes(16).hex()
KGU = xor_strings(A1, HPWi)

A4 = int(w,16)*P
A5 = int(w,16)*X

DIDi = xor_strings(IDi, str(A5)[:32])

M1 = xor_strings((str(R1)+str(SIDk)),KGU)
V1 = hash_256(IDi, R1, KGU, M1)

section1 = time.time()-start_time
MSG1 = [DIDi, A4, M1, V1]
NodeA.send(pickle.dumps(MSG1))

M4, V4 = pickle.loads(NodeA.recv(1024))
start2 = time.time()

M4_KGu = xor_strings(M4, KGU[:96])
GIDj = M4_KGu[:32]
R2 = M4_KGu[32:64]
R3 = M4_KGu[64:]
SK =hash_256(IDi, GIDj, SIDk, R1, R2, R3)
V4_star = hash_256(KGU, SK, R2, R3)
if V4 != V4_star:
    raise ValueError("MSG4验证失败")

end_time = time.time()

print("NodeA_section:",(end_time-start2+section1)*1000)
print("Alltime:",(end_time-start_time)*1000)

# 关闭连接
NodeA.close()
