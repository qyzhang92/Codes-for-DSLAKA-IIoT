import json
import pickle
import socket
import struct
import time

from FunctionMod import *


G = ecp.generator()
# socke配置
NodeA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
NodeA.connect(server_address)

# 获取注册信息
client_type = "A"


deltT = 1.0
sk_A = secrets.token_bytes(32).hex()
pk_A = int(sk_A,16)*G

# 初始化阶段 注册阶段
CA = secrets.token_bytes(16).hex()
RA = get_puf(CA)
m0 = secrets.token_bytes(16).hex()
r0 = secrets.token_bytes(16).hex()
a = secrets.token_bytes(32).hex()
RA_1 = xor_strings(RA, a)

LL = [client_type, pk_A,r0, m0, RA_1]
NodeA.send(pickle.dumps(LL))

MN1, ID_A,TID_A = pickle.loads(NodeA.recv(1024))
MN1_1 = xor_strings(MN1, a)

k1_star = big.modadd(int(m0, 16), big.modmul(int(r0, 16), int(sk_A,16), curve.r),
                         curve.r) % curve.r  # (m + r*s)

h1 = hash_512(RA, pk_A)
xA = xor_strings(sk_A + str(k1_star), h1)

# 等待Server的通知 收到通知就开始计时
ID_B = pickle.loads(NodeA.recv(1024))

# 认证开始========================================================================================
t1 = time.time()

RA = get_puf(CA)

tmp =xor_strings(xA, hash_512(RA,pk_A))
sk_A = tmp[:64]; k1_star = tmp[64:]  #

XGWN_A = xor_strings(MN1_1, RA)

# 构造变色龙随机数
r1 = secrets.token_bytes(16).hex()
T1 = time.time()
r1_1 = hash_256(r1,T1)[:32]
m1 = big.modsub(int(k1_star), big.modmul(int(r1_1, 16), int(sk_A, 16), curve.r), curve.r)

# 计算L1
L1 = xor_strings(r1, hash_256(XGWN_A, T1, m1, pk_A)[:32])
DID1_1 = xor_strings(hash_256(r1_1,m1,T1),ID_B)[:32]

msg1 = [L1, m1, DID1_1, T1, TID_A]
NodeA.send(pickle.dumps(msg1))
# msg1发送成功

t2 = time.time()

NodeA_sectionOne_T1 = (t2-t1)*1000

# 接收消息4
L4, M3, T4= pickle.loads(NodeA.recv(1024))
t3 = time.time()

if time.time()-T4>deltT:
    raise ValueError("T3过期")

temp = xor_strings(L4, hash_256(XGWN_A, T4, ID_A, pk_A))
ID_B = temp[:32]
r2 = temp[32:]

M3_1 = hash_256(r2, L4, XGWN_A, T4, ID_B)

if M3 != M3_1:
    raise ValueError("MSG4验证失败")

sk = hash_256(r1,r2,ID_A,ID_B)
TID_A_new = hash_256(r1_1,TID_A,ID_B)
t4 = time.time()


print("NodeA_section:",((t4-t3))*1000 + NodeA_sectionOne_T1)

print("总时间: ", (t4 - t1) * 1000)

# 关闭连接
NodeA.close()
