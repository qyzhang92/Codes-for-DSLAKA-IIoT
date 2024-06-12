import pickle
import socket
import time

from FunctionMod import *

import json

NodeB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('127.0.0.1', 123)
NodeB.connect(server_address)

client_type = "B"

G = ecp.generator()


deltT = 1.0

# 初始化阶段 注册阶段
sk_B = secrets.token_bytes(32).hex()
pk_B = int(sk_B,16)*G

CB = secrets.token_bytes(16).hex()
RB = get_puf(CB)
m0 = secrets.token_bytes(16).hex()
r0 = secrets.token_bytes(16).hex()
a = secrets.token_bytes(32).hex()
RB_1 = xor_strings(RB, a)

LL = [client_type, pk_B, r0, m0, RB_1]
NodeB.send(pickle.dumps(LL))

MN1, ID_B,TID_B = pickle.loads(NodeB.recv(1024))
MN1_1 = xor_strings(MN1, a)[:64]

k2_star = big.modadd(int(m0, 16), big.modmul(int(r0, 16), int(sk_B,16), curve.r),
                         curve.r) % curve.r  # (m + r*s)

h1 = hash_512(RB, pk_B)
xB = xor_strings(sk_B + str(k2_star), h1)

# 接受Msg2==========================================================================
L2, M2, T2 = pickle.loads(NodeB.recv(1024))
startT1 = time.time()

if time.time()-T2>deltT:
    raise ValueError("T2过期")

RB = get_puf(CB)
XGWN_B = xor_strings(MN1_1, RB)

sk2_B = xor_strings(xB, hash_512(RB,pk_B))[:64]
k2_star = xor_strings(xB, hash_512(RB,pk_B))[64:]  #

temp = xor_strings(L2, hash_256(XGWN_B, T2, ID_B, pk_B))
ID_A = temp[:32]
r1 = temp[32:]

M2_1 = hash_256(r1, L2, XGWN_B, T2, ID_A)

if M2 != M2_1:
    raise ValueError("M2完整性校验失败，认证结束")

# 构造变色龙随机数
r2 = secrets.token_bytes(16).hex()
T3 = time.time()
r2_1 = hash_256(r2, T3)[:32]
TID_B_new = hash_256(r2_1,TID_B,ID_A)
m2 = big.modsub(int(k2_star), big.modmul(int(r2_1, 16), int(sk2_B,16), curve.r), curve.r)
# 建立会话密钥

SK = hash_256(r1, r2, ID_A, ID_B)
# 计算L3
L3 = xor_strings(r2, hash_256(XGWN_B,T3, m2, pk_B)[:32])
DID2_1 = xor_strings(hash_256(r2_1,m2,T3),ID_A)

# 发送msg3====================================================================================
msg3 = [L3, m2, DID2_1,T3, TID_B]
NodeB.send(pickle.dumps(msg3))

print("NodeB_section:",(time.time()-startT1)*1000)

# 关闭连接
NodeB.close()
