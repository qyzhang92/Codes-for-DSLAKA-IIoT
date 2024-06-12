import pickle
import socket
import time

from FunctionMod import *

import json

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
GateWay_address = ('127.0.0.2', 234)
server_socket.bind(GateWay_address)
server_socket.listen(1)

# 等待设备连接
Device, client_address = server_socket.accept()

#收到设备请求
SIDj = Device.recv(1024).decode()

# 连接到服务器 新建socket
server_address = ('127.0.0.1', 123)
GateWay = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
GateWay.connect(server_address)

client_type = "GateWay"
GIDk = secrets.token_bytes(16).hex()
GateWay.send(json.dumps([client_type, GIDk, SIDj]).encode())

xGk, XGk = json.loads(GateWay.recv(1024).decode())



XSj = hashlib.sha3_256(SIDj.encode() + xGk.encode()).hexdigest()
aaa = xor_strings(SIDj,GIDk)
Device.send(XSj.encode())

# 开始认证===============================================================================================================
M2, M6, M7, M8 = pickle.loads(GateWay.recv(1024))
start1 = time.time()


r_1 = xor_strings(M6, hashlib.sha3_256(XGk.encode() + str(M2).encode()).hexdigest()[:32])
SIDj_11 = xor_strings(M7, hashlib.sha3_256(M6.encode() + r_1.encode() + XGk.encode()).hexdigest()[:32])
M8_1 = hashlib.sha3_256(
    str(M2).encode() + M6.encode() + M7.encode() + r_1.encode() + SIDj_11.encode() + XGk.encode()).hexdigest()

if M8_1 != M8:
    raise ValueError("MSG2校验失败,M8校验失败")

rg = secrets.token_bytes(16).hex()
Xsj_1 = hashlib.sha3_256(SIDj_11.encode()+xGk.encode()).hexdigest()
M9 = xor_strings(hashlib.sha3_256(Xsj_1.encode()+str(M2).encode()).hexdigest()[:32], rg)
M10 = hashlib.sha3_256(str(M2).encode() + M9.encode() + rg.encode() + SIDj_11.encode() + Xsj_1.encode()).hexdigest()

section1 = time.time()-start1
Msg3 = [M2, M9, M10]
Device.send(pickle.dumps(Msg3))


# 接受Msg4
M11, M12 = pickle.loads(Device.recv(1024))
start2 = time.time()

M12_1 = hashlib.sha3_256(
    str(M2).encode() + str(M11).encode() + rg.encode() + Xsj_1.encode() + SIDj_11.encode()).hexdigest()

if M12 != M12_1:
    raise ValueError("Msg4验证失败，M12验证失败")

M13 = hashlib.sha3_256(
    str(M11).encode() + str(M2).encode() + SIDj_11.encode() + r_1.encode() + XGk.encode()).hexdigest()

print("gateway_section:",(time.time()-start2+section1)*1000)
Msg5 = [M11, M13]
GateWay.send(pickle.dumps(Msg5))


