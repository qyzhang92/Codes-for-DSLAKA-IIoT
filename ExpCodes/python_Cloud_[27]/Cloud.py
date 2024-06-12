import json
import pickle
import socket
import time

from FunctionMod import *
from NodeRegister import *

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
server_socket.bind(server_address)
server_socket.listen(2)

clients = {}
HoneyList = []
y, GIDk, IDi, ai =  "", "", "", ""
XGk = ""
client_type = ""
x = secrets.token_bytes(16).hex()
SIDj = ""
xGk = secrets.token_bytes(16).hex()
Y = ""
P = ecp.generator()
a = ""
Trig=""

while len(clients) < 2:
    client_socket, client_address = server_socket.accept()
    SIDj_GIDk, PWi, Bioi, a_1 = "", "", "", ""

    revice = json.loads(client_socket.recv(1024).decode())

    if len(revice) > 3:
        client_type, IDi, PWi, Bioi, a_1, y, ai, a, Trig = revice
        Y = a_mul_p(int(y, 16), P)
    elif len(revice) == 3:
        client_type, SIDj_GIDk, SIDj = revice

    clients[client_type] = client_socket

    if client_type == "A":
        IDi,Trig, ai, Honey_list = C_getUser(IDi, PWi, Bioi, a_1, "C", y, ai, a, Trig)
        clients.get("A").send(SIDj.encode())

    elif client_type == "GateWay":
        GIDk = SIDj_GIDk
        XGk = hashlib.sha3_256(GIDk.encode()+x.encode()).hexdigest()
        # GateWay注册
        L = [xGk, XGk]
        clients.get("GateWay").send(json.dumps(L).encode())


# 全部连接与注册完成 通知NodeA开始计时
clients.get("A").send("start".encode())


# 开始认证
M2, M3, M4, M5 = pickle.loads(clients.get("A").recv(1024))
start1 = time.time()

M1_1 = a_mul_p(int(y,16), M2)

IDi_1 = xor_strings(M3, hash_256(M2, M1_1))
ai_1 = IDi_1[32:]
IDi_1 = IDi_1[:32]

if ai_1 != ai:
    raise ValueError("Cloud认证User失败")

ki_1 = hash_256(IDi_1, y, Trig)
SIDj_1 = xor_strings(M4, hash_256(M1_1, M2, M3)[:32])
M5_1 = hash_256(ki_1, IDi_1, M1_1, M2, SIDj_1)

if M5 != M5_1:
    raise ValueError("Msg1验证失败，M5验证失败")

r = secrets.token_bytes(16).hex()
XGk_1 = hash_256(GIDk, x)
M6 = xor_strings(hash_256(XGk_1, M2)[:32], r)
M7 = xor_strings(hash_256(M6, r, XGk_1)[:32], SIDj_1)

M8 = hash_256(M2, M6, M7, r, SIDj_1, XGk_1)

section1 = time.time()-start1
Msg2 = [M2, M6, M7, M8]
clients.get("GateWay").send(pickle.dumps(Msg2))

# 接受MSg5
M11, M13 = pickle.loads(clients.get("GateWay").recv(1024))
start2 = time.time()

M13_1 = hashlib.sha3_256(str(M11).encode()+str(M2).encode()+SIDj_1.encode()+r.encode()+XGk_1.encode()).hexdigest()

if M13!=M13_1:
    raise ValueError("Msg5验证失败，M13验证失败")


M14 = hashlib.sha3_256(str(M1_1).encode()+str(M2).encode()+IDi_1.encode()+SIDj_1.encode()+ki_1.encode()+str(M11).encode()).hexdigest()

print("cloud_section:",(time.time()-start2+section1)*1000)

Msg6 =[M11, M14]
clients.get("A").send(pickle.dumps(Msg6))


