import pickle
import socket
import time

from FunctionMod import *

import json

NodeB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
NodeB.connect(server_address)

P = ecp.generator()
# 注册
client_type = "B"
SNid = secrets.token_bytes(16).hex()

LL = [client_type, SNid ]
NodeB.send(pickle.dumps(LL))
Kgs = pickle.loads(NodeB.recv(1024))

# 开始认证===========================================================================
D1, D6, D7 = pickle.loads(NodeB.recv(1024))
start1 = time.time()

rG_1 = xor_strings(Kgs,D6)
D7_1 = hashlib.sha3_256(str(D1).encode()+rG_1.encode()+Kgs.encode()+SNid.encode()).hexdigest()

if D7 != D7_1:
    raise ValueError("MSG2验证失败")


b = secrets.token_bytes(32).hex()

D8 = int(b,16)*P
SK = hashlib.sha3_256(str(D1).encode()+str(D8).encode()+str(int(b,16)*D1).encode()).hexdigest()

D9 = hashlib.sha3_256(Kgs.encode()+str(D8).encode()+rG_1.encode()+SNid.encode()).hexdigest()
D10 = hashlib.sha3_256(SNid.encode()+SK.encode()).hexdigest()

print("NodeB_section:",(time.time()-start1)*1000)
MSG3 = [D8, D9, D10]
NodeB.send(pickle.dumps(MSG3))

# 关闭连接
NodeB.close()
