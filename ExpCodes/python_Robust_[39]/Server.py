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
SNid, B1, B2, B3 = "", "", "", ""
delt_T = 1.0
while len(clients) < 2:
    client_socket, client_address = server_socket.accept()

    #获得注册信息
    revice = pickle.loads(client_socket.recv(1024))

    if revice[0] == "B":
        client_type, SNid = revice
        clients[client_type] = client_socket
        Kgs = hashlib.sha3_256(SNid.encode()+w.encode()).hexdigest()
        client_socket.send(pickle.dumps(Kgs))
    else:
        client_type, IDu, HPWu, Bio = revice
        clients[client_type] = client_socket
        B1 = hashlib.sha3_256(IDu.encode()+HPWu.encode()+Bio.encode()).hexdigest()
        B2 = hashlib.sha3_256(IDu.encode()+w.encode()).hexdigest()
        B3 = xor_strings(hashlib.sha3_256(HPWu.encode()+Bio.encode()).hexdigest(),B2)
        m1 = [B1, B3, X]
        client_socket.send(pickle.dumps(m1))

# print("All clients connected!")
# 通知A开始认证 并把SNid给A
clients.get("A").send(pickle.dumps(SNid))

# 开始认证
DIDu, D1, D3, D4 = pickle.loads(clients.get("A").recv(1024))
start1 = time.time()

D2_1 = int(x,16)*D1

IDu_1 = xor_strings(DIDu,hashlib.sha3_256(str(D2_1).encode()).hexdigest()[:32])
B2_1 = hashlib.sha3_256(IDu_1.encode()+w.encode()).hexdigest()
SNid_1 = xor_strings(xor_strings(D3, B2_1[:32]),hashlib.sha3_256(str(D2_1).encode()).hexdigest()[:32])
D4_1 = hashlib.sha3_256(B2_1.encode()+str(D2_1).encode()+SNid_1.encode()).hexdigest()

if D4 != D4_1:
    raise ValueError("MSG1验证失败")

rG = secrets.token_bytes(32).hex()
D5 = hashlib.sha3_256(SNid_1.encode()+w.encode()).hexdigest()
D6 = xor_strings(D5,rG)
D7 = hashlib.sha3_256(str(D1).encode()+rG.encode()+D5.encode()+SNid_1.encode()).hexdigest()

section1 = time.time()-start1
MSG2 = [D1, D6, D7]
clients.get("B").send(pickle.dumps(MSG2))

D8, D9, D10 = pickle.loads(clients.get("B").recv(1024))
start2 = time.time()

D9_1 = hashlib.sha3_256(D5.encode()+str(D8).encode()+rG.encode()+SNid_1.encode()).hexdigest()

if D9 != D9_1:
    raise ValueError("MSG3验证失败")

D11 = hashlib.sha3_256(IDu_1.encode()+str(D1).encode()+str(D8).encode()+B2_1.encode()).hexdigest()

print("Server_section:",(time.time()-start2+section1)*1000)

MSG4 = [D8, D10, D11]
clients.get("A").send(pickle.dumps(MSG4))

# 关闭连接
for client_socket in clients.values():
    client_socket.close()
server_socket.close()
