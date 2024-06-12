import json
import pickle
import socket
import time

from FunctionMod import *

import sys   #sys模块提供了一系列有关Python运行环境的变量和函数。

from python1_Ours.nist256.curve import r

print(sys.version)


# Chaos mapping parameters
ri= 399202342336 # 155033642076
p= 115792089210356248762697446949407573530086143415290314195533631308867097853951
rj = 3983623723 # 1594324474

G = ecp.generator()
x = secrets.token_bytes(32).hex()

# 设备端m1的计算开销
m0 = secrets.token_bytes(16).hex()
r0 = secrets.token_bytes(16).hex()
sk_A = secrets.token_bytes(32).hex()
k1_star = big.modadd(int(m0, 16), big.modmul(int(r0, 16), int(sk_A,16), curve.r),
                         curve.r) % curve.r  # (m + r*s)
r1 = secrets.token_bytes(16).hex()
T1 = time.time()
r1_1 = hash_256(r1,T1)[:32]

t1 = time.perf_counter()
for i in range(1000):
    m1 = big.modsub(int(k1_star), big.modmul(int(r1_1, 16), int(sk_A, 16), curve.r), curve.r)
t2 = time.perf_counter()
print("SDA get m1:",(t2-t1))   # res*1000 /1000 = res


CA =""
# random
t1 = time.perf_counter()
for i in range(1000):
    CA = secrets.token_bytes(16).hex()
t2 = time.perf_counter()
print("getRandom:",(t2-t1))   # res*1000 /1000 = res


timestamp = int(time.time())  # 获取当前时间戳
timestamp_binary = bin(timestamp)[2:]  # 转换为二进制并去掉开头的'0b'
print("timestamp_binary:",timestamp_binary)

# hash function
t1 = time.perf_counter()
for i in range(1000):
    hash_256(x)
t2 = time.perf_counter()
print("Hash:",(t2-t1))

# PUF
t1 = time.perf_counter()
for i in range(1000):
    RA = get_puf(CA)
t2 = time.perf_counter()
print("PUF:",(t2-t1))


m0 = secrets.token_bytes(16).hex()
r0 = secrets.token_bytes(16).hex()
x = secrets.token_bytes(32).hex()
pk1 = a_mul_p(int(x,16), G)
k1_star = big.modadd(int(m0, 16), big.modmul(int(r0, 16), int(x,16), curve.r),
                         curve.r) % curve.r  # (m + r*s)

# Construct Chameleon Random Numbers
r1 = secrets.token_bytes(16).hex()
T1 = time.time()
r1_1 = hash_256(r1,T1)[:32]
m1 = big.modsub(int(k1_star), big.modmul(int(r1_1, 16), int(x, 16), curve.r), curve.r)
#  Chameleon hash function
t1 = time.perf_counter()
for i in range(100):
    CH1_2 = ecp.mul(G, int(m1), pk1, int(r1_1, 16))
t2 = time.perf_counter()
print("CH:",(t2-t1)*1000/100)


# Tm
aaa = int(x,16)
t1 = time.perf_counter()
for i in range(10):
    pk = aaa*G
t2 = time.perf_counter()
print("Tm:",(t2-t1)*1000/10)

# chaotic map
xx = secrets.token_bytes(16).hex()
t1 = time.perf_counter()
for i in range(100):
    T(ri,int(xx,16),p)
t2 = time.perf_counter()
print("Tcm:",(t2-t1)*1000/100)


# public_key = aaa*G
#
# # 将公钥转换为字节串
# public_key_bytes = public_key.toBytes(compress=True)  # 可以选择使用压缩格式或非压缩格式
#
# # 将字节串还原为椭圆曲线点
# restored_public_key = ecp.generator()
# restored_public_key.fromBytes(public_key_bytes)
# print(public_key)
# print(restored_public_key)
# print(aaa*restored_public_key)
# # 验证还原是否成功
# if restored_public_key == public_key:
#     print("Success")
# else:
#     print("Fail")