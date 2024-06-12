import hashlib
import json
import pickle
import socket
import time

from FunctionMod import *


P = ecp.generator()
# socke配置  连接服务器
NodeA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 123)
NodeA.connect(server_address)


# 获取注册信息


IDu = secrets.token_bytes(16).hex()
PWu = secrets.token_bytes(16).hex()
Bio = secrets.token_bytes(16).hex()
ru = secrets.token_bytes(16).hex()
HPWu = hashlib.sha3_256(PWu.encode()+ru.encode()).hexdigest()
delt_T = 1.0

# 初始化阶段 注册阶段
client_type = "A"
LL = [client_type, IDu, HPWu, Bio]
NodeA.send(pickle.dumps(LL))

B1, B3, X = pickle.loads(NodeA.recv(1024))

# 开始认证通知
SNid = pickle.loads(NodeA.recv(1024))

#开始认证    开始计时
start_time = time.time()
B1_1 = hashlib.sha3_256(IDu.encode()+hashlib.sha3_256(PWu.encode()+ru.encode()).hexdigest().encode()+Bio.encode()).hexdigest()

if B1_1 != B1:
    raise ValueError("本地验证失败")


a = secrets.token_bytes(32).hex()
B2 = xor_strings(B3,hashlib.sha3_256(hashlib.sha3_256(PWu.encode()+ru.encode()).hexdigest().encode()+Bio.encode()).hexdigest())

D1 = int(a,16)*P
D2 = int(a,16)*X


DIDu = xor_strings(IDu,hashlib.sha3_256(str(D2).encode()).hexdigest()[:32])
D3 = xor_strings(xor_strings(SNid,B2[:32]),hashlib.sha3_256(str(D2).encode()).hexdigest()[:32])
D4 = hashlib.sha3_256(B2.encode()+str(D2).encode()+SNid.encode()).hexdigest()

section1 = time.time()-start_time
Msg1 = [DIDu, D1, D3, D4]
NodeA.send(pickle.dumps(Msg1))

D8, D10, D11 = pickle.loads(NodeA.recv(1024))
start2 = time.time()

D11_1 = hashlib.sha3_256(IDu.encode()+str(D1).encode()+str(D8).encode()+B2.encode()).hexdigest()
if D11!=D11_1:
    raise ValueError("MSG4验证失败")


SK_1 = hashlib.sha3_256(str(D1).encode()+str(D8).encode()+str(int(a,16)*D8).encode()).hexdigest()
D10_1 = hashlib.sha3_256(SNid.encode()+SK_1.encode()).hexdigest()

if D10!=D10_1:
    raise ValueError("最后一步验证失败")


end_time = time.time()

print("NodeA_section:",(end_time-start2+section1)*1000)
print("time:",(end_time-start_time)*1000)

# 关闭连接
NodeA.close()
