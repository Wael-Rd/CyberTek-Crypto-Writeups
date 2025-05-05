#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import inverse
from Crypto.Cipher import AES
from collections import namedtuple
import hashlib

HOST = '185.91.127.50'
PORT = 1234

Point = namedtuple("Point", "x y")

class EllipticCurve:
    INF = Point(0, 0)

    def __init__(self, a, b, Gx, Gy, p):
        self.a = a
        self.b = b
        self.p = p
        self.G = Point(Gx, Gy)

    def add(self, P, Q):
        if P == self.INF:
            return Q
        if Q == self.INF:
            return P
        if P.x == Q.x and P.y == (-Q.y % self.p):
            return self.INF
        if P != Q:
            tmp = (Q.y - P.y) * inverse(Q.x - P.x, self.p) % self.p
        else:
            tmp = (3 * P.x**2 + self.a) * inverse(2 * P.y, self.p) % self.p
        Rx = (tmp**2 - P.x - Q.x) % self.p
        Ry = (tmp * (P.x - Rx) - P.y) % self.p
        return Point(Rx, Ry)

    def multiply(self, P, n):
        R = self.INF
        while n > 0:
            if n & 1:
                R = self.add(R, P)
            n >>= 1
            P = self.add(P, P)
        return R
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -0x3
Gx = 0x55b40a88dcabe88a40d62311c6b300e0ad4422e84de36f504b325b90c295ec1a
Gy = 0xf8efced5f6e6db8b59106fecc3d16ab5011c2f42b4f8100c77073d47a87299d8
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
E = EllipticCurve(a, b, Gx, Gy, p)

def main():
    conn = remote(HOST, PORT)

    try:
        
        print(conn.recvuntil(b"Point x: ").decode())
        Px = 82794344854243450371984501721340198645022926339504713863786955730156937886079
        Py = 33552521881581467670836617859178523407344471948513881718969729275859461829010
        conn.sendline(str(Px).encode())
        conn.recvuntil(b"Point y: ")
        conn.sendline(str(Py).encode())
        conn.recvuntil(b"Your point: ")
        print(conn.recvline().decode())
        conn.recvuntil(b"My point: ")
        Q_line = conn.recvline().decode()
        Qx, Qy = map(int, Q_line.strip().strip("()").split(", "))
        Q = Point(Qx, Qy)
        possible_s = [0, 1, 2]
        possible_keys = []
        for s in possible_s:
            output = E.multiply(Q, s).x & ((1 << 128) - 1)
            key = hashlib.sha1(str(output).encode()).digest()[:16]
            possible_keys.append(key)
        for _ in range(3):
            conn.recvuntil(b"Ciphertext: ")
            cipher = bytes.fromhex(conn.recvline().decode().strip())
            iv = cipher[:16]
            ct = cipher[16:]
            for key in possible_keys:
                try:
                    aes = AES.new(key, AES.MODE_CBC, iv)
                    msg = aes.decrypt(ct)
                    conn.sendline(msg.hex().encode())
                    print(conn.recvline().decode()) 
                    break
                except:
                    continue
        conn.recvuntil(b"flag: ")
        flag = conn.recvline().decode().strip()
        print(f"Flag: {flag}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()