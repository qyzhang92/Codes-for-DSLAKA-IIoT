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

# 等待节点B连接自己
NodeA_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
GateWay_address = ('127.0.0.2', 234)
NodeA_B.bind(GateWay_address)
NodeA_B.listen(1)
A_B, client_address = NodeA_B.accept()


# 获取注册信息
client_type = "A"

IDi = secrets.token_bytes(16).hex()
PWi = secrets.token_bytes(16).hex()
bi = secrets.token_bytes(16).hex()
ID_INj = "b2b8d5ed2a4d8b5001ac882322ef4e42"
Bio = secrets.token_bytes(16).hex()
MIDi = hashlib.sha3_256(IDi.encode()+bi.encode()).hexdigest()
MPWi = hashlib.sha3_256(PWi.encode()+Bio.encode()).hexdigest()
delt_T = 1.0

# 初始化阶段 注册阶段
LL = [client_type, MIDi, MPWi]
NodeA.send(pickle.dumps(LL))

G1,G2,G3, Gpub, ID_CGk = pickle.loads(NodeA.recv(1024))


Li = xor_strings(bi,hashlib.sha3_256(IDi.encode()+Bio.encode()+PWi.encode()).hexdigest()[:32])
G2_star = xor_strings(str(G2),hashlib.sha3_512(bi.encode()+Bio.encode()+PWi.encode()).hexdigest())
G3_star = xor_strings(str(G3),hashlib.sha3_512(Bio.encode()+bi.encode()+PWi.encode()).hexdigest())
G4 = hashlib.sha3_256(str(G1).encode()+PWi.encode()+bi.encode()+Bio.encode()).hexdigest()

# 等待Server的通知 收到通知就开始计时
response = NodeA.recv(1024).decode()


# 认证开始  拥有pk1 xA C1 ID1 x1_1===========================================================
start_time = time.time()


MPWi_star = hash_256(PWi,Bio)
bi_star = xor_strings(Li, hash_256(IDi,Bio,PWi)[:32])
MIDi_star = hash_256(IDi,bi_star)
G1 = a_mul_p(int(hash_256(MIDi_star),16),Gpub)  # 1111111

G2 = xor_strings(str(G2_star),hash_512(bi_star,Bio,PWi))
G3 = xor_strings(G3_star,hash_512(Bio,bi_star,PWi))
G4_star = hash_256(G1,PWi,bi_star,Bio)

if G4_star != G4:
    raise ValueError("本地验证失败")


x = secrets.token_bytes(32).hex()
TS1 = time.time()

Mx = a_mul_p(int(x,16),P) ### 111111
HIDi = xor_strings(MIDi_star,hash_256(xor_strings(str(G1),str(G3))[:128],TS1))
A1 = a_mul_p(int(x,16),Gpub.add(int(hash_256(ID_INj),16)*P))  ## 22222222
A2 = xor_strings(str(A1),hash_512(G2,G1,Mx,TS1))
A3 = hash_256(xor_strings(str(G1),str(G3))[:128],MIDi_star,TS1,A2)
DID_INj = xor_strings(ID_INj,hash_256(G1,TS1)[:32])

section1 = time.time()-start_time

MSG1 = [A3,HIDi,G2,DID_INj,Mx,TS1]
NodeA.send(pickle.dumps(MSG1))


DIDINj_star, NM2, My, SKV_ji, TS3 = pickle.loads(A_B.recv(1024))
startT2 = time.time()

TS3_1 = time.time()
if TS3_1 - TS3 > delt_T:
    raise ValueError("时间过期")

ID_INj_star = xor_strings(DIDINj_star, hash_256(MIDi_star,ID_CGk,TS3)[:32])
if ID_INj != ID_INj_star:
    raise ValueError("MSG3-ID验证失败")

if NM2 != hash_256(MIDi_star,ID_INj,ID_CGk,Mx,My,TS3):
     raise ValueError("NM2验证失败")

A4 = big.modadd(big.modmul(int(NM2,16),int(x,16),curve.r), int(hash_256(ID_INj), 16), curve.r)*My  # 12111
SK_ij = hash_256(A4,MIDi_star,ID_INj,Mx,My)

if SKV_ji != hash_256(SK_ij,TS3):
    raise ValueError("最后一步验证失败")


end_time = time.time()

print("NodeA_section:",( end_time-startT2+section1)*1000)
print("All_time:",(end_time-start_time)*1000)
# 关闭连接
NodeA.close()
