import math
import secrets
import time

from python7_Chaotic_Map.FunctionMod import hash_256

mi1 = secrets.token_bytes(16).hex()
print(int(mi1, 16))
print()
x = hash_256(mi1)[:32]
print(hash_256(mi1)[:32])
print(int(x, 16))


# nist-256模
# p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
# 递归
def T(n, x):
    if n == 0:
        return 1
    if n == 1:
        return x
    return (2 * x * T(n - 1, x) % p - T(n - 2, x) % p) % p


# 非递归
def T2(n, x):
    stack = []
    stack.append(1)
    stack.append(x)

    for i in range(2, n + 1):
        next_num = ((2 * x * stack[-1]) % p - stack[-2]) % p

        a = stack.pop()
        b = stack.pop()
        stack.append(a)
        stack.append(next_num)

    return stack[-1]


def T(n, x):
    return math.cos(math.acos(x) * n)


# 普通递归法
def T2(n, x, p):
    if n == 0:
        return 1
    elif n == 1:
        return x
    elif n % 2 == 0:
        temp = T2(n // 2, x, p)
        re = 2 * temp * temp - 1
        return re % p
    else:
        re = 2 * T2((n + 1) // 2, x, p) * T2((n - 1) // 2, x, p) - x
        return re % p


t11 = time.time()
# print(T2(n1,x,p))   # T2(n2,x,p)
t22 = time.time()

print("普通递归:", (t22 - t11) * 1000)


# 快速递归
def T3(n, x, p):
    if n == 0:
        return 1
    elif n == 1:
        return x
    elif n % 2 == 0:  # 偶数
        temp = T3(n // 2, x, p)
        return (2 * temp * temp - 1) % p
    else:
        if n % 4 == 1:
            odd = (n + 3) // 4
            even = (n - 1) // 4  # 偶数
        else:
            odd = (n - 3) // 4
            even = (n + 1) // 4
        A = T3(even, x, p)
        B = T3(odd, x, p)
        C = (2 * A * A - 1) % p
        D = (2 * A * B - x) % p
        return (2 * C * D - x) % p

p = 115792089210353 # 115792089210356248762697446949407573530086143415290314195533631308867097853951
ri = 11579208921 # 2934623723

x1 = hash_256(mi1)
t1 = time.time()
Ag = T3(ri,int(x1[:32],16),p)
t2 = time.time()
print("什么啊:",(t2-t1)*1000)

n1 = 1590234233  # 155033642076
x = int(secrets.token_bytes(32).hex(), 16)  # 8909654478045



n2 = 1534623723  # 1594324474

t1 = time.time()
print(T3(n1, T3(n2, x, p), p))
t2 = time.time()
print("快速递归:", (t2 - t1) * 1000)
t11 = time.time()
T3(n1, x, p)
t22 = time.time()
print("快速递归:", (t22 - t11) * 1000)

t11 = time.time()
T3(n1, x, p)
t22 = time.time()
print("快速递归:", (t22 - t11) * 1000)


def pow_2(c, d, a, p):
    '''带根式的多项式的平方，不拆根号'''
    x = c * c + d * d * a
    y = 2 * c * d
    return (x % p, y % p)


def mul(x1, y1, x2, y2, a, p):
    '''带根式的乘法，保证不拆根号'''
    x = x1 * x2 + y1 * y2 * a
    y = x1 * y2 + x2 * y1
    return (x % p, y % p)


def T4(n, x, p):
    a = x * x - 1
    c, d = x, 1
    e, f = 1, 0  # 初始值
    j, k = 1, 0  # 初始j,k
    while n > 0:
        ep = n & 1
        n >>= 1
        if ep:
            j, k = mul(e, f, c, d, a, p)
            e, f = j, k
        c, d = pow_2(c, d, a, p)
    return j


t3 = time.time()
print(T4(n1, T4(n2, x, p), p))  # ," ",T4(n2,T3(n1,x,p),p)
t4 = time.time()
print("矩阵特征值法:", (t4 - t3) * 1000)

t5 = time.time()
print(T4(n2, T4(n1, x, p), p))  # ," ",T4(n2,T3(n1,x,p),p)
t6 = time.time()

print("矩阵特征值法:", (t6 - t5) * 1000)

ri = int(secrets.token_bytes(16).hex(), 16)  # 256bit
rj = int(secrets.token_bytes(16).hex(), 16)
x = int(secrets.token_bytes(16).hex(), 16)
