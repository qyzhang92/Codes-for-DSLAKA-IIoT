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

delt_T = 1.0

X_GWN_Ui = secrets.token_bytes(16).hex()
X_GWN = secrets.token_bytes(16).hex()
Skeyj =""
SIDj = ""
while len(clients) < 2:
    client_socket, client_address = server_socket.accept()

    #获得注册信息
    revice = pickle.loads(client_socket.recv(1024))

    if revice[0] == "A":
        client_type, x1, x2 = revice
        Ci = xor_strings(xor_strings(x1,x2),hash_256(X_GWN,hash_256(X_GWN_Ui)))

        clients[client_type] = client_socket

        client_socket.send(pickle.dumps(Ci))
    else:
        client_type, SIDj = revice
        clients[client_type] = client_socket
        Skeyj = hash_256(SIDj,X_GWN)
        Keyj = xor_strings(Skeyj, X_GWN)
        client_socket.send(pickle.dumps(Skeyj))

# print("All clients connected!")
# 通知A开始认证 并把SNid给A
clients.get("A").send(pickle.dumps(SIDj))

# 开始认证
Ei_1, DIDi_1, VGWN, Gi, SIDj_1, TS1, len1 = pickle.loads(clients.get("A").recv(1024))
start1 = time.time()

if time.time()-TS1>delt_T:
    raise ValueError("T1时间过期")
Mi = hash_256(X_GWN,hash_256(X_GWN_Ui))
DIDi = xor_strings(DIDi_1, hash_256(Ei_1,Mi, TS1))
Ag_star = xor_strings(Gi, hash_256(DIDi,Mi, TS1)[:len1])
SIDj = xor_strings(SIDj_1,hash_256(DIDi, TS1)[:32])


if VGWN!= hash_256(DIDi,Ag_star,Gi,SIDj,TS1):
    raise ValueError("MSG1验证失败")

Ei = xor_strings(Ei_1,hash_256(DIDi, Mi, TS1))
TS2 = time.time()
SIDj_11 = xor_strings(hash_256(SIDj,Skeyj,TS2), DIDi)
Hj = xor_strings(Skeyj[:len1], Ag_star)
VSNj = hash_256(Skeyj, SIDj, Ag_star, Hj, TS2)
Ei_11 = xor_strings(Ei, hash_256(Skeyj, TS2))

print("Server_section:",(time.time()-start1)*1000)

MSG2 = [Hj, VSNj, SIDj_11, Ei_11, TS2, len1]
clients.get("B").send(pickle.dumps(MSG2))



# 关闭连接
for client_socket in clients.values():
    client_socket.close()
server_socket.close()
