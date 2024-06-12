from FunctionMod import *



def C_getUser(IDi, PWi, Bioi, a_1, msg, y, ai, a,Treg):
    # 应该是Cloud的随机数
    RPWi = hashlib.sha3_256(PWi.encode() + Bioi.encode() + a_1.encode()).hexdigest()

    ki = hashlib.sha3_256(IDi.encode() + y.encode() + Treg.encode()).hexdigest()
    Bi_1 = xor_strings(hashlib.sha3_256(RPWi.encode() + IDi.encode()).hexdigest(), ki)
    Honey_list = []


    RPWi_new = hashlib.sha3_256(PWi.encode() + Bioi.encode() + a.encode()).hexdigest()

    Ai = hashlib.sha3_256(IDi.encode() + RPWi_new.encode() + ki.encode()).hexdigest()
    Bi = xor_strings(hashlib.sha3_256(RPWi_new.encode() + IDi.encode()).hexdigest(), ki)

    if msg == "C":
        return IDi, Treg, ai, Honey_list  #
    elif msg == "A":
        return Ai, Bi, a, xor_strings(Ai[:32], ai), Bioi

# x是Cloud私钥
def C_getGWN(x,GIDk):
   XGk = hashlib.sha3_256(x.encode()+GIDk.encode())
   return XGk

# 网关私钥 xGk
def C_getDevice(SIDj,xGk):
    XSj = hashlib.sha3_256(SIDj.encode()+xGk.encode())
    return XSj