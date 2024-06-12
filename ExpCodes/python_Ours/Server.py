import json
import pickle
import socket
import time

from FunctionMod import *
from nist256.curve import p

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
server_socket.bind(server_address)
server_socket.listen(2)

clients = {}
G = ecp.generator()
sk_RC = secrets.token_bytes(32).hex()
pk_RC = a_mul_p(int(sk_RC,16), G)

ID_A, pk_A, RA_1, TID_A = "", "", "", ""
ID_B, pk_B, RB_1, TID_B = "", "", "", ""
XGWN_A,XGWN_B ="",""
# r1_star =   hex(int("0"*32,16))[2:]
# r2_star = hex(int("0"*32,16))[2:]
# modd = "F" * 64
deltT = 1.0
while len(clients) < 2:
    client_socket, client_address = server_socket.accept()

    #获得注册信息
    revice = pickle.loads(client_socket.recv(1024))

    if revice[0]=="A":
        clients["A"] = client_socket
        client_type, pk_A,r0, m0, RA_1 = revice

        ID_A = str(ecp.mul(G, int(m0, 16), pk_A, int(r0, 16)))[:32]  #取128bit

        B0 = secrets.token_bytes(16).hex()
        TID_A = secrets.token_bytes(16).hex()

        XGWN_A = hash_256(ID_A, B0, pk_A)
        MN1 = xor_strings(RA_1, XGWN_A)

        msg0_A = [MN1, ID_A, TID_A]
        clients["A"].send(pickle.dumps(msg0_A))
    else:
        clients["B"] = client_socket
        client_type, pk_B, r0, m0, RB_1 = revice

        ID_B = str(ecp.mul(G, int(m0, 16), pk_B, int(r0, 16)))[:32]
        B0 = secrets.token_bytes(16).hex()
        TID_B = secrets.token_bytes(16).hex()

        XGWN_B = hash_256(ID_B, B0, pk_B)
        MN1 = xor_strings(RB_1, XGWN_B)

        msg0_B = [MN1, ID_B, TID_B]
        clients["B"].send(pickle.dumps(msg0_B))

# 通知A 让他准备计时
clients.get("A").send(pickle.dumps(ID_B))

L1, m1, DID1_1, T1, TID_A = pickle.loads(clients.get("A").recv(1024))
startT1 = time.time()

if time.time()-T1>deltT:
    raise ValueError("T1时间过期")

h2 = hash_256(XGWN_A, T1, m1, pk_A)
r1 = xor_strings(L1, h2)[:32]
r1_1 = hash_256(r1, T1)[:32]
ID_A_1 = str(ecp.mul(G, int(m1), pk_A, int(r1_1, 16)))[:32]

if ID_A != ID_A_1:
     raise ValueError("Msg1验证失败")


# ==============================================
T2 = time.time()

ID_B = xor_strings(hash_256(r1_1,m1,T1),DID1_1)[:32]
L2 = xor_strings(ID_A+str(r1), hash_256(XGWN_B, T2, ID_B, pk_B))
M2 = hash_256(r1, L2, XGWN_B, T2, ID_A)


msg2 = [L2, M2, T2]
clients.get("B").send(pickle.dumps(msg2))
server_section1_T = time.time()-startT1
# =====================================
L3, m2, DID2_1,T3, TID_B = pickle.loads(clients.get("B").recv(1024))

startT2 = time.time()

if time.time()-T3>deltT:
    raise ValueError("T3过期")

h2 = hash_256(XGWN_B, T3, m2, pk_B)
r2 = xor_strings(L3, h2[:32])
r2_1 = hash_256(r2, T3)[:32]
ID_B_1 = str(ecp.mul(G, int(m2), pk_B, int(r2_1, 16)))[:32]  # m0*p + r0*pk2


if ID_B != ID_B_1:
    raise ValueError("Msg3验证失败")

#==================================
T4 = time.time()
ID_A = xor_strings(hash_256(r2_1,m2,T3),DID2_1)[:32]
TID_A_new = hash_256(r1_1,TID_A,ID_B)
TID_B_new = hash_256(r2_1,TID_B,ID_A)

sk = hash_256( r1, r2, ID_A, ID_B)

L4 = xor_strings(ID_B+r2, hash_256(XGWN_A, T4, ID_A,pk_A))
M3 = hash_256(r2, L4, XGWN_A, T4, ID_B)
msg4 = [L4, M3, T4]

clients.get("A").send(pickle.dumps(msg4))

print("server_section:",(time.time()-startT2+server_section1_T)*1000)

# 关闭连接
for client_socket in clients.values():
    client_socket.close()
server_socket.close()
