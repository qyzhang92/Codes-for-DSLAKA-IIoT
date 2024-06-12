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
w = secrets.token_bytes(16).hex()
x = secrets.token_bytes(32).hex()
X = int(x,16)*P
K = secrets.token_bytes(16).hex()
GIDj = secrets.token_bytes(16).hex()
delt_T = 1.0
SIDk,KGs ="",""
while len(clients) < 2:
    client_socket, client_address = server_socket.accept()

    #获得注册信息
    revice = pickle.loads(client_socket.recv(1024))

    if revice[0] == "A":
        client_type, IDi, HPWi = revice
        clients[client_type] = client_socket
        K_GU = hash_256(IDi,K)
        A1 = xor_strings(K_GU,HPWi)
        TEMP = secrets.token_bytes(16).hex()
        L = [A1, TEMP, X]
        client_socket.send(pickle.dumps(L))
    else:
        client_type, SIDk = revice
        clients[client_type] = client_socket
        KGs = hash_512(SIDk, K)
        client_socket.send(pickle.dumps(KGs))

# print("All clients connected!")
# 通知A开始认证 并把SNid给A
clients.get("A").send(pickle.dumps(SIDk))


# 开始认证
DIDi, A4, M1, V1 = pickle.loads(clients.get("A").recv(1024))
start1 = time.time()

A5_star = int(x,16)*A4
IDi_star = xor_strings(DIDi, str(A5_star)[:32])
KGU = hash_256(IDi_star, K)
R1_star = xor_strings(M1, KGU)[:32]
SIDk = xor_strings(M1, KGU)[32:]


V1_star = hash_256(IDi_star, R1_star, KGU, M1)
if V1!=V1_star:
    raise ValueError("MSG1验证失败")


R2 = secrets.token_bytes(16).hex()
KGs = hash_512(SIDk, K)
M2 = xor_strings((str(IDi_star)+str(GIDj)+str(R1_star)+str(R2)),KGs)
V2 = hash_256(IDi_star,GIDj,KGs,R1_star,R2)

section1 = time.time()-start1
MSG2 = [M2, V2]
clients.get("B").send(pickle.dumps(MSG2))

M3, V3 = pickle.loads(clients.get("B").recv(1024))
start2 = time.time()

R3 = xor_strings(M3,KGs[:32])
SK = hash_256(IDi_star, GIDj, SIDk, R1_star, R2, R3)
V3_star = hash_256(R3, KGs, SK)
if V3!=V3_star:
    raise ValueError("MSG3验证失败")


M4 = xor_strings(str(GIDj)+str(R2)+str(R3), KGU[:96])
V4 = hash_256(KGU, SK, R2, R3)

print("Server_section:",(time.time()-start2+section1)*1000)
MSG4 = [M4, V4]
clients.get("A").send(pickle.dumps(MSG4))


# 关闭连接
for client_socket in clients.values():
    client_socket.close()
server_socket.close()
