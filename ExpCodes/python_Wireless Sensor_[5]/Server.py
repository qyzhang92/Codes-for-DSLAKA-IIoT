import json
import pickle
import socket
import time
import base64

from FunctionMod import *

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
server_socket.bind(server_address)
server_socket.listen(2)

clients = {}
P = ecp.generator()
x = secrets.token_bytes(32).hex()
X = int(x,16)*P
XGWN = secrets.token_bytes(16).hex()
deltT = 1.0
SIDj = ""
fj = ""
while len(clients) < 2:
    client_socket, client_address = server_socket.accept()

    #获得注册信息
    revice = pickle.loads(client_socket.recv(1024))

    if revice[0] == "A":
        client_type, IDi, Mpi = revice
        clients[client_type] = client_socket
        ri_1 = secrets.token_bytes(16).hex()
        MI_i = hash_256(ri_1, IDi)
        fi = hash_256(MI_i, XGWN)
        ei = xor_strings(Mpi, fi)
        L = [MI_i, ei]
        client_socket.send(pickle.dumps(L))
    else:
        client_type, SIDj = revice
        clients[client_type] = client_socket
        fj = hash_256(SIDj, XGWN)
        client_socket.send(pickle.dumps(fj))

# print("All clients connected!")
# 通知A开始认证 并把SNid给A
clients.get("A").send(pickle.dumps(SIDj))


# 开始认证
MI_i, Ni, SIDj, Aj, T1, T2 = pickle.loads(clients.get("B").recv(1024))
start1 = time.time()
fj_1 = hash_256(SIDj, XGWN)
Aj_1 = hash_256(fj_1, Ni, T2)
fi_1 = hash_256(MI_i, XGWN)
Yi_1 = hash_256(fi_1, T1)[:44]
Ni_1 = hash_256(Yi_1, MI_i, SIDj)


if Ni!=Ni_1 or Aj != Aj_1:
    raise ValueError("MSG2验证失败")
T3 = time.time()

Fij = xor_strings(Yi_1, hash_256(fj_1, T3)[:44])

Hj = hash_256(Yi_1)
Ei = hash_256(fi_1, Ni_1)

print("server_section:",(time.time()-start1)*1000)

MSG4 = [Fij, Hj, Ei, T3]
clients.get("B").send(pickle.dumps(MSG4))


# 关闭连接
for client_socket in clients.values():
    client_socket.close()
server_socket.close()
