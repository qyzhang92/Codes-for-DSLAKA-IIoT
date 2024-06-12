import json
import socket
import time
import pickle
from FunctionMod import *
# from python.NodeRegister import A_getA_Register
from NodeRegister import *

P = ecp.generator()

# socke配置
NodeA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('127.0.0.1', 123)
NodeA.connect(server_address)



client_type = "A"
IDi = secrets.token_bytes(16).hex()
PWi = secrets.token_bytes(16).hex()
Bioi = secrets.token_bytes(16).hex()
a_1 = secrets.token_bytes(16).hex()
y = secrets.token_bytes(32).hex()
Trig = secrets.token_bytes(16).hex()
Y = a_mul_p(int(y,16),P)

ai = secrets.token_bytes(16).hex()
a = secrets.token_bytes(16).hex()

LL = [client_type, IDi, PWi, Bioi, a_1, y, ai, a, Trig]
NodeA.send(json.dumps(LL).encode())

SIDj = NodeA.recv(1024).decode()

Ai, Bi, a, Ai_a, Bioi = C_getUser(IDi, PWi, Bioi, a_1, client_type, y, ai, a, Trig)



# 开始认证通知
response = NodeA.recv(1024).decode()
start_time = time.time()

# 开始认证  =============================================================================================================
# RPWi_star = hashlib.sha3_256(PWi.encode() + Bioi.encode() + a.encode()).hexdigest()
RPWi_star = hash_256(PWi,Bioi,a)
ki_star = xor_strings(Bi, hash_256(RPWi_star, IDi))

Ai_star = hash_256(IDi, RPWi_star, ki_star)


if Ai_star != Ai:
    raise ValueError("Ai验证失败")

ri = secrets.token_bytes(32).hex()
ai_star = xor_strings(Ai[:32],Ai_a)


M1 = a_mul_p(int(ri,16),Y)
M2 = a_mul_p(int(ri,16),P)
M3 = xor_strings(hash_256(M2,M1),(IDi+ai_star))

M4 = xor_strings(hash_256(M1, M2, M3)[:32],SIDj)
M5 = hash_256(ki_star, IDi, M1, M2, SIDj)

section1 = time.time()-start_time
Msg1 = [M2, M3,M4,M5]
NodeA.send(pickle.dumps(Msg1))



# 接受MSg6
M11, M14 = pickle.loads(NodeA.recv(1024))
start_time2 = time.time()

M14_star = hash_256(M1, M2, IDi, SIDj, ki_star, M11)

if M14!=M14_star:
    raise ValueError("Msg6验证失败，M14验证失败")


M11_1 = a_mul_p(int(ri,16),M11)
SK = hash_256(M2, M11, M11_1)

end_time = time.time()
print("NodeA_section:",(end_time-start_time2+section1)*1000)
print("all_time: ",(end_time-start_time)*1000)

# 关闭连接
NodeA.close()
