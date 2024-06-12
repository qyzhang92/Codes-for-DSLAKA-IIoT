import json
import pickle
import socket
import time

from FunctionMod import *




server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
server_socket.bind(server_address)
server_socket.listen(2)

clients = {}
P = ecp.generator()
g_pri = secrets.token_bytes(32).hex()
Gpub = a_mul_p(int(g_pri,16),P)
X_CGk = secrets.token_bytes(16).hex()
G1, G2, G3 = "","",""
SKCG_BRC = ""
ID_CGk = secrets.token_bytes(16).hex()
delt_T = 1.0
while len(clients) < 2:
    client_socket, client_address = server_socket.accept()

    #获得注册信息
    revice = pickle.loads(client_socket.recv(1024))

    if revice[0] == "A":
        client_type, MIDi, MPWi = revice
        clients[client_type] = client_socket
        G1 = a_mul_p(big.modmul(int(g_pri, 16), int(hash_256(MIDi), 16), curve.r), P)
        G2 = xor_strings(str(G1), hash_512(MPWi, MIDi))
        G3 = xor_strings(str(G1), hash_512(X_CGk))

        LL = [G1, G2, G3, Gpub, ID_CGk]
        client_socket.send(pickle.dumps(LL))
    else:
        client_type, SKCG_BRC = revice
        clients[client_type] = client_socket
        client_socket.send(pickle.dumps(ID_CGk))

# 通知A开始认证
clients.get("A").send("start".encode())


# print("All clients connected!")
# 开始认证

A3,HIDi,G2,DID_INj,Mx,TS1 = pickle.loads(clients.get("A").recv(1024))

startT1 = time.time()

TS1_1 = time.time()

if TS1_1 - TS1 > delt_T:
    raise ValueError("时间过期")


MIDi_star = xor_strings(HIDi, hash_256(hash_512(X_CGk),TS1))
G1_star = big.modmul(int(g_pri,16),int( hash_256(MIDi_star),16),curve.r)*P
ID_INj = xor_strings(DID_INj, hash_256(str(G1_star),str(TS1))[:32])
A1_star = big.modadd(int(g_pri,16),int( hash_256(ID_INj),16),curve.r)*Mx
A2 = xor_strings(str(A1_star),hash_512(G2,G1_star,Mx,TS1))

if A3 !=  hash_256(hash_512(X_CGk),MIDi_star,TS1,A2):
    raise ValueError("Msg1验证失败")

TS2 = time.time()
h1 = hash_256(SKCG_BRC,ID_INj)
GI1 =xor_strings( hash_256(h1,str(TS2)),MIDi_star)
SK_kj = hash_256(str(TS2),ID_CGk,MIDi_star,h1)
GI2 = hash_256(ID_INj,MIDi_star,str(Mx),SK_kj,str(TS2))


MSG2 = [GI1, GI2, Mx, TS2]
clients.get("B").send(pickle.dumps(MSG2))
print("server_section:",(time.time()-startT1)*1000)


# 关闭连接
for client_socket in clients.values():
    client_socket.close()
server_socket.close()
