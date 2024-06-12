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

# 等待节点B连接自己
NodeA_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
GateWay_address = ('127.0.0.2', 234)
NodeA_B.bind(GateWay_address)
NodeA_B.listen(1)
A_B, client_address = NodeA_B.accept()

# 获取注册信息
IDi = secrets.token_bytes(16).hex()
PWi = secrets.token_bytes(16).hex()
bi = secrets.token_bytes(32).hex()
mi1 = secrets.token_bytes(32).hex()
mi2 = secrets.token_bytes(32).hex()
DPWi = hash_256(IDi,bi)
delt_T = 1.0
ri= 399202342336 # 155033642076  混沌映射我选的随机数，如果选128bit的
86258452304265726032150489035946585925 # 128bit的随机数
p= 115792089210356248762697446949407573530086143415290314195533631308867097853951


# 初始化阶段 注册阶段
client_type = "A"
LL = [client_type, xor_strings(DPWi,mi1), xor_strings(DPWi,mi2)]
NodeA.send(pickle.dumps(LL))

Ci = pickle.loads(NodeA.recv(1024))
Bio = secrets.token_bytes(16).hex()
Li = xor_strings(bi,hash_256(Bio,PWi))
RBi = hash_256(IDi,Bio, PWi)
Ci_1 = xor_strings(xor_strings(xor_strings(Ci,mi1),mi2),hash_256(Bio, IDi))


# 开始认证通知
SIDj = pickle.loads(NodeA.recv(1024))

# 开始认证 =========================================================================================================
start_time = time.time()

bi_star = xor_strings(Li,hash_256(Bio,PWi))
if RBi != hash_256(IDi,Bio,PWi):
    raise ValueError("本地验证失败")

Ci = xor_strings(Ci_1,hash_256(Bio,IDi))
DIDi = hash_256(IDi,bi_star)
Ji = xor_strings(xor_strings(Ci,DIDi),DPWi)
# ri = int(secrets.token_bytes(16).hex(),16)
TS1 = time.time()
Ei = hash_256(Ji,hash_256(Bio,PWi),TS1)

x1 = hash_256(DIDi,SIDj,Ei)


Ag = T(ri,int(x1[:32],16),p)

len1 = len(hex(Ag)[2:])

Gi = xor_strings(str(Ag),hash_256(DIDi,Ji,TS1)[:len1])
VGWN = hash_256(DIDi,str(Ag),Gi,SIDj,TS1)
Ei_1 = xor_strings(Ei,hash_256(DIDi,Ji,TS1))


DIDi_1 = xor_strings(DIDi,hash_256(Ei_1,Ji,TS1))
SIDj_1 = xor_strings(SIDj,hash_256(DIDi,TS1)[:32])

section1 = time.time()-start_time

MSG1 = [Ei_1, DIDi_1, VGWN, Gi, SIDj_1, TS1, len1]
NodeA.send(pickle.dumps(MSG1))

Pj,Nj_1,TS3, len2 = pickle.loads(A_B.recv(1024))
start2 = time.time()

if time.time()-TS3>delt_T:
    raise ValueError("TS3时间过期")

Nj = int(xor_strings(Nj_1, hash_256(DIDi, SIDj, TS3)[:len2]))


SKij_star = hash_256(T(ri,Nj,p)%p,DIDi,TS3)

if Pj != hash_256(SKij_star, Nj, TS3):
    raise ValueError("MSG3验证失败")

end_time = time.time()

print("A_section:",(end_time-start2+section1)*1000)
print("总时间是:",(end_time-start_time)*1000)

# 关闭连接
NodeA.close()
