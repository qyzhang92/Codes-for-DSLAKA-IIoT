import pickle
import socket
import time

from FunctionMod import *
import json

Device = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.2', 234)
Device.connect(server_address)


client_type = "Di"
P = ecp.generator()
SIDj = secrets.token_bytes(16).hex()
Device.send(SIDj.encode())

XSj = Device.recv(1024).decode()

# 开始认证 =============================================================================
M2, M9, M10 = pickle.loads(Device.recv(1024))
start1 = time.time()

rg_1 = xor_strings(M9,hashlib.sha3_256(XSj.encode()+str(M2).encode()).hexdigest()[:32])
M10_1 = hashlib.sha3_256(str(M2).encode()+M9.encode()+rg_1.encode()+SIDj.encode()+XSj.encode()).hexdigest()


if M10_1!=M10:
    raise ValueError("Msg3验证失败，M10验证失败")

rj = secrets.token_bytes(32).hex()


M = a_mul_p(int(rj,16),M2)
M11 = a_mul_p(int(rj,16),P)


SK = hashlib.sha3_256(str(M2).encode()+str(M11).encode()+str(M).encode()).hexdigest()
M12 = hashlib.sha3_256(str(M2).encode()+str(M11).encode()+rg_1.encode()+XSj.encode()+SIDj.encode()).hexdigest()

print("Device_section:",(time.time()-start1)*1000)

Msg4 = [M11, M12]
Device.send(pickle.dumps(Msg4))



