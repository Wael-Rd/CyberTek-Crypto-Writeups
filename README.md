<p align="center">
  <img src="logo.png" alt="CyberTek Logo" width="200"/>
</p>

#  CyberTek Crypto Challenges Writeup

---
Welcome to an exciting journey through six CyberTek cryptography challenges: **ezRSA+**, **syb3lik**, **ezRSA**, **hash101**, **ezMATH**, and **QUANTUM-BB84**. These puzzles test our skills in RSA, elliptic curves, complex number cryptography, and quantum key distribution. Let’s dive into the solutions with clear explanations and code! 🔍

---

## 🌟 Challenge 1: ezRSA+

### 🧩 Overview

**ezRSA+** is an RSA-based puzzle with a non-standard setup. We’re given:

- **Modulus** `n`: A 2048-bit product of primes `p` and `q`.
- **Gift**: `gift = lcm(p-1, q-1)`, the least common multiple of `p-1` and `q-1`.
- **Ciphertext** `c`: The encrypted flag.
- **Public Exponent** `e = 54722`: An even number, unlike typical RSA exponents.

Our goal is to decrypt `c` to recover the flag using provided scripts.

### 📜 Provided Code

#### `ezRSA+.py` (Generation)

```python
from gmpy2 import lcm, powmod, invert, gcd, mpz
from Crypto.Util.number import getPrime
from sympy import nextprime
from random import randint
p = getPrime(1024)
q = getPrime(1024)
n = p * q
Gift = lcm(p-1, q-1)
e = 54722
flag = b'Securinets{************************}'
m = int.from_bytes(flag, 'big')
c = powmod(m, e, n)
print('n: ', n)
print('gift: ', Gift)
print('c: ', c)
```

#### `solve-ezRSA+.py` (Solution)

```python
from gmpy2 import gmpy2
from sympy import *
from Crypto.Util.number import *
from gmpy2 import *
n = 13728072685156741377404150425205631443747392211645406309821952464884331839500660091404615205484663315179498906864876162929868493420336276192156099521150339282470630953469611085437224052161460129663129547310926192893341619454915953118715058171977147066317269896376724883820180899402434512292566796749398111502473542732607316355557328921316283618213871098567271196431800090492300304212847275750179886503039215991909837428710156630693135682325426114078495419061820909231115403979614189558606039050413984458538116069601632480294219634360386703588847446863845008025983945423567543794021906790848314441606689357737905909563
gift = 6864036342578370688702075212602815721873696105822703154910976232442165919750330045702307602742331657589749453432438081464934246710168138096078049760575169641235315476734805542718612026080730064831564773655463096446670809727457976559357529085988573533158634948188362441910090449701217256146283398374699055751118198777650695454615530482951660961544166396578283667142565618591497016334455055350938943362197575592521100825066433004771444154210987704052051040288836744095463753808594035278694589327484569389020741543251702700667513056685389713599050726328691960352622502962105472351764626676370456260033635003038517137440
c = 3897202753351171417806440449162253531395405377803044003217991116217971016506600948065164877285545799340546937193322755230707527397368424640480664241753517484164761944319894868882426722594454576876625420488377262526739673467619263387408839662824937023214149263803640159742545622344630669216904190233871749527631674452260232530281575849653585972385578444216125636730119911313151517537269714296154036861122654185597691703454563773256890035154537098997493260268453710430687746797244882420524259921657137572797747094392685502401072404020354566364264697901210781619004459011537797946656047840958181530940668465723197315443
phi = gift * 2
e = 54722
d = inverse(e//2, phi)
print(long_to_bytes(gmpy2.iroot(pow(c, int(d), n), 2)[0]))
```

### 🧠 Solution

**ezRSA+** uses an even public exponent and a special `gift`. Here’s the solution:

1. **Understand the Gift**:

   - The `gift` is `lcm(p-1, q-1)`. The RSA totient is: \[ \\phi = (p-1)(q-1) \]
   - LCM and GCD are related: \[ lcm(a, b) = \\frac{a \\cdot b}{gcd(a, b)} \] So: \[ gift = lcm(p-1, q-1) = \\frac{(p-1)(q-1)}{gcd(p-1, q-1)} = \\frac{\\phi}{gcd(p-1, q-1)} \] Rearranging: \[ \\phi = gift \\cdot gcd(p-1, q-1) \]

2. **Why** `phi = gift * 2`**?**:

   - The script sets `phi = gift * 2`, implying: \[ gcd(p-1, q-1) = 2 \]
   - **Reason**: `p` and `q` are 1024-bit primes (odd), so `p-1` and `q-1` are even (divisible by 2). Their GCD is at least 2. For large random primes, additional shared factors are unlikely, and the challenge ensures `gcd(p-1, q-1) = 2`.
   - Thus: \[ \\phi = gift \\cdot 2 \]

3. **Analyze the Exponent**:

   - `e = 54722 = 2 \cdot 27361` is even, so `gcd(e, \phi) = 2`. However, `e/2 = 27361` is coprime with `phi`.
   - The ciphertext is: \[ c = m^e \\mod n = (m^2)^{e/2} \\mod n \]

4. **Decrypt**:

   - Compute the private key for `e/2`: \[ d = inverse(e/2, \\phi) \]
   - Decrypt to get `m^2`: \[ m^2 = c^d \\mod n \]
   - Take the square root (unique since `m` is small): \[ m = \\sqrt{m^2} \]
   - Convert to bytes: `long_to_bytes(m)`.

5. **Run the Script**:

   ```bash
   python solve-ezRSA+.py
   ```

   **Flag**: `Securinets{diff1cult_rsa_1s_e@sy_xxxxxxxxxxxxxxxxxx}`

> **💡 Insight**: The `gift` bypasses factoring `n`, and the even `e` requires a square root step.

---

##  Challenge 2: syb3lik

###  Overview

**syb3lik** is an elliptic curve-based challenge. We must decrypt three AES-encrypted messages to win the flag. We’re given:

- An elliptic curve over prime `p` with generator `G` and parameters `a`, `b`.
- The ability to choose a point `P`.
- A server-generated point `Q`.
- Three ciphertexts (IV + AES-CBC encrypted messages) using keys from a custom RNG.

### 📜 Key Code

#### `syb3lik.py` (Server)

- Defines the elliptic curve and point operations.
- RNG:

  ```python
  class RNG:
      def __init__(self, seed, P, Q):
          self.seed = seed
          self.P = P
          self.Q = Q
      def next(self):
          s = E.multiply(self.P, self.seed).x
          self.seed = s
          r = E.multiply(self.Q, s).x
          return r & ((1 << 128) - 1)
  ```
- Keys: `key = hashlib.sha1(str(rng.next()).encode()).digest()[:16]`.

#### `solve-syb3lik.py` (Solution)

```python
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
        if P == self.INF: return Q
        if Q == self.INF: return P
        if P.x == Q.x and P.y == (-Q.y % self.p): return self.INF
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
            if n & 1: R = self.add(R, P)
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
```

### 🧠 Solution

The challenge uses a weak RNG based on elliptic curve operations:

1. **Analyze the RNG**:

   - Initialized with a 128-bit `seed`, our point `P`, and server’s point `Q = k \cdot G`.
   - `rng.next()`:
     - Computes `s = (seed \cdot P).x`, updates `seed = s`.
     - Outputs `r = (s \cdot Q).x & ((1 << 128) - 1)`.
   - Key: `sha1(str(r))[:16]`.

2. **Exploit Weakness**:

   - The solution assumes the first `s` (after one iteration) is small (`0`, `1`, or `2`).
   - For small `s`, `r = (s \cdot Q).x & ((1 << 128) - 1)` is predictable.
   - Choose a valid `P` (provided) and receive `Q`.

3. **Generate Keys**:

   - For `s = 0, 1, 2`, compute: \[ r = (s \\cdot Q).x \\mod 2^{128} \]
   - Compute keys: `sha1(str(r))[:16]`.

4. **Decrypt Messages**:

   - For each ciphertext, try each key to decrypt with AES-CBC.
   - Send decrypted messages to the server.

5. **Get the Flag**:

   - After three correct decryptions, the server sends the flag.

**Why it Works**:

- The provided `P` likely causes `s` to be small, reducing the keyspace.
- Testing `s = 0, 1, 2` covers likely values.

**Flag**: (Retrieved from server)

> **💡 Insight**: The RNG’s small output space after one iteration makes brute-forcing feasible.

---

##  Challenge 3: ezRSA

###  Overview

**ezRSA** splits the flag into two parts, encrypted with RSA:

- **Part 1**: `n1`, `c1`, `hint1 = x1*p + y1*q - 0x114`, `hint2 = x2*p + y2*q - 0x514`, `x1, x2 < 2^11`, `y1 < 2^114`, `y2 < 2^514`, `e = 65537`.
- **Part 2**: `n2`, `c2`, `hint = (514*p - 114*q)^(n-p-q) mod n`, `e = 65537`.

### 📜 Provided Code

#### `ezRSA.py` (Generation)

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint
import gmpy2

FLAG = b"Securinets{fake_flag}"
flag1 = FLAG[:15]
flag2 = FLAG[15:]

def crypto1():
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 0x10001
    x1 = randint(0, 2**11)
    y1 = randint(0, 2**114)
    x2 = randint(0, 2**11)
    y2 = randint(0, 2**514)
    hint1 = x1 * p + y1 * q - 0x114
    hint2 = x2 * p + y2 * q - 0x514
    c = pow(bytes_to_long(flag1), e, n)
    return n, c, hint1, hint2

def crypto2():
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 0x10001
    base = 514 * p - 114 * q
    if gmpy2.gcd(base, n) != 1:
        return crypto2()
    hint = pow(base, n - p - q, n)
    c = pow(bytes_to_long(flag2), e, n)
    return n, c, hint
```

#### `solve-ezRSA.py` (Solution)

```python
from Crypto.Util.number import long_to_bytes, GCD, inverse
from sympy import symbols, Eq, solve
import gmpy2
from time import time

# Provided values for n1, c1, hint1_1, hint1_2, n2, c2, hint2
n1 = 17133148046143797165017730375597289530602158028429944779983444823593671605728696760707606738847150876776519894045217810388409701384072421590392968524375955916507823776162510079895700562646835788011800520337937704615635306289168216307665399404031018949735193172100225735909636924437569185929492038545196092972960297905982632893890787419482159770431344522116527036201598586369085757773314426049500902475473177431363557038395657806560370300306706059012442783132369369350628639781060137595721832807319390801398137648698928672867177773995670825566134111079174159239101482706812795991237388012357927911630841919559245442739
c1 = 4094937807220296101358408851424262929750988035041993627850534712565996992094000512967630300791352527154625306962414867753591221363693916448966483255530614217885580454720720641253332118237537440051946532907641955845483416619095134662509840253812781576310878784591663430053047987447475708140480121636618395831250510117200509333605124128145870930647265467920267344539753064735167386545660647828206124891287175446017966717019920553342927228890087343280071112510862140833826479877801232117593654838278821199307141579032526405678990449420445809041058468474305650336828256297532450001452216904611227171797955149555143477718
hint1_1 = 1417683353478586992067438086229793323416913783809353250874689324311972765774836799847429293466442928475422037826303816898535071306273562508845905689378918746032837800053636488658031499976792764718268505575407946150748419010275476300202076854241230935906475699512343753355286955622923977898942712651799833724565178714184692034775357869141010487
hint1_2 = 4749661439430389358405550542063909868213747270525702547402092544406487874709429642555949130032466454382334641130540473068434142578768408325301143093750827761882507730936605176595216754091677744714919287038006752762347694510116538556332765522758073560556266468846208022896346606902538427669856238568765365978223181188905099091513645090676416371013048463225788585130893971758278617785526189877652405664936579330215883993728971863629032002882564146995539068777128878
n2 = 18068567064261038518451130069768230252925394564736533024187703334825336454886448407090088348452595070458336668250419482661638361373450459850835767587761722954413083982514277919406004499502885943472477895556276660040953185931376296902284469353825050587304012517513247967754777788001838716348606714332334538788201430464485363734660456562024986734152928091263156143615149592980274161755678945125062170716729348523067644744426708593882877711953982861493403958993848550526256016902429071488473941772589660778104212700555005540122212612365463852729274218607394956630763488676576869601152789556228037515043453323337472277991
c2 = 6452222504600591648121251587920712582963148771580741929172351881239425922784513699512532061444614614609391410286353601720327046622231049005658116411754352227490801529014594348308963303772062254901652888559896825415389034733271006594941644917629919990763776001183032619103870848577391785551672481057190506876114452029948162543870548034568567442924323360038280882415012772147391566279712154129564997239722227974794360302087896758125259562888176664397646358819182427241829674373503417371457790392184387209716311324714808669095157695565002646045189502280268845828600567651482969005359563573572251811602713922177191003918
hint2 = 5195693241260445897097321710972100810400259519783433393398159440561701799126382060456234917874344289439864117100722798185458262143658282896917802516329358582994213097001191571143826375004485259104868801996120890757148582196149647199540494383651166407543057620789887895167410096549414244098786863912409959069814597745519211527857425343815882427610172825176577224089923894285025472550569585831582506401544146498641249900033651527868736985840628734756715498428020842996312174216895171975389026965398869535173633769370779438765766845754475098905984514467900526634556548437606917066905934127816117117060198390407887836423
e = 0x10001

print("--------------------------------------------------part1--------------------------------------------------")
start_time = time()
# Part 1: Brute-force x1, x2 to find q
for i in range(2**11 + 1):
    for j in range(2**11 + 1):
        temp = (hint1_1 + 0x114) * i - (hint1_2 + 0x514) * j
        g = GCD(temp, n1)
        if g != 1 and g != n1:
            p = g
            q = n1 // p
            if p * q == n1 and gmpy2.is_prime(p) and gmpy2.is_prime(q):
                phi = (p - 1) * (q - 1)
                if GCD(e, phi) == 1:
                    d = inverse(e, phi)
                    flag1 = long_to_bytes(pow(c1, d, n1))
                    break
    else:
        continue
    break
print("---------------------------------------------------end---------------------------------------------------")

print("--------------------------------------------------part2--------------------------------------------------")
# Part 2: Solve linear system
temp = inverse(hint2, n2)
p, q = symbols('p q')
equation1 = Eq(514 * p - 114 * q, temp)
equation2 = Eq(p * q, n2)
solutions = solve((equation1, equation2), (p, q))
for sol in solutions:
    p_val, q_val = sol
    p_val = int(p_val)
    q_val = int(q_val)
    if gmpy2.is_prime(p_val) and gmpy2.is_prime(q_val) and p_val * q_val == n2:
        p, q = p_val, q_val
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        flag2 = long_to_bytes(pow(c2, d, n2))
        break
print("---------------------------------------------------end---------------------------------------------------")

end_time = time()
print(f"Flag: {flag1 + flag2}")
print(f"Time taken: {end_time - start_time} seconds")
```

### 🧠 Solution

The flag is split into `flag1` and `flag2`.

#### Part 1: Recover `flag1`

- **Hints**: \[ hint1 = x1 \\cdot p + y1 \\cdot q - 0x114 \] \[ hint2 = x2 \\cdot p + y2 \\cdot q - 0x514 \]
- **Strategy**:
  - Rewrite: \[ hint1 + 0x114 = x1 \\cdot p + y1 \\cdot q \] \[ hint2 + 0x514 = x2 \\cdot p + y2 \\cdot q \]
  - Eliminate `q`: \[ (hint1 + 0x114) \\cdot x2 - (hint2 + 0x514) \\cdot x1 = (y1 \\cdot x2 - y2 \\cdot x1) \\cdot q \]
  - Brute-force `x1, x2 < 2^11` to compute `temp` and find `p = GCD(temp, n1)`.
  - Compute `q = n1 // p`, `phi = (p-1)(q-1)`, `d = inverse(e, phi)`.
  - Decrypt: `flag1 = long_to_bytes(pow(c1, d, n1))`.

#### Part 2: Recover `flag2`

- **Hint**: \[ hint = (514 \\cdot p - 114 \\cdot q)^{n-p-q} \\mod n \] Since `n - p - q = \phi`: \[ hint \\cdot (514 \\cdot p - 114 \\cdot q)^{-1} = 1 \\mod n \]
- **Strategy**:
  - Compute `temp = inverse(hint, n2) = 514 \cdot p - 114 \cdot q`.
  - Solve: \[ 514 \\cdot p - 114 \\cdot q = temp \] \[ p \\cdot q = n2 \]
  - Compute `phi`, `d`, and decrypt `flag2`.

**Flag**: `Securinets{~:L1n34r_Pr1m3E_114!!!!}`

> **💡 Insight**: Part 1 brute-forces small coefficients, while Part 2 uses a modular inverse.

---

##  Challenge 4: hash101

###  Overview

**hash101** uses RSA over complex numbers and ChaCha20. We’re given:

- `n = p * q`, `e = 3`.
- `mh = [(m.re >> 128 << 128), (m.im >> 128 << 128)]`: High bits of `m`.
- `C = [c.re, c.im]`: `c = m^3 mod n`.
- `enc`: ChaCha20-encrypted flag with key `sha256(str(m.re + m.im))`.

### 📜 Provided Code

#### `hash101.py` (Generation)

```python
from Crypto.Util.number import *
from Crypto.Cipher import ChaCha20
import hashlib

class Complex:
    def __init__(self, re, im):
        self.re = re
        self.im = im
    def __mul__(self, c):
        re_ = self.re * c.re - self.im * c.im
        im_ = self.re * c.im + self.im * c.re
        return Complex(re_, im_)
    def __rshift__(self, m):
        return Complex(self.re >> m, self.im >> m)
    def __lshift__(self, m):
        return Complex(self.re << m, self.im << m)
    def tolist(self):
        return [self.re, self.im]

def complex_pow(c, exp, n):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = result * c
            result.re = result.re % n
            result.im = result.im % n
        c = c * c
        c.re = c.re % n
        c.im = c.im % n
        exp >>= 1
    return result

bits = 128
p = getPrime(1024)
q = getPrime(1024)
n = p * q
m = Complex(getRandomRange(1, n), getRandomRange(1, n))
e = 3
c = complex_pow(m, e, n)
print(f"n = {n}")
print(f"mh = {(m >> bits << bits).tolist()}")
print(f"C = {c.tolist()}")
print(f"enc = {ChaCha20.new(key=hashlib.sha256(str(m.re + m.im).encode()).digest(), nonce=b'Pr3d1ctmyxjj').encrypt(flag)}")
```

#### `solve-hash101-part1.py` (Recover `m`)

```python
import itertools
def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m + 1):
        base = N ^ (m - i) * f ^ i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B * monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

a_high = 9245771018720220165473157258175831420845484046990577190296029604996039184849924744238787339787096796382850266844371448691375170396739491301451548991057032485978061144056260933752650980783771487344689316401102847985381621048521201687177603399044498048732688462040589607869984341015544647397642092122769568708297556825246074288582430980733145683273350366571896960594430727649100079655830025058633724307540529672811566836398624593727396066740314639545029222687337384717592445245722536069434136020157395788948993000390733755319302103392189475532183523915862334850604599798634272974026356149404797966367508667070177869824
b_high = 8347635539592661235359577950860151375883964148441684625020802052680277442439812780330120330085363714762855342232831950915319740418302743720208454337743927246468200856158081923166989832989086672997741730659482257489996283828553436914665779494607346634534503720771705435695354568128843631458940027136419501885422264693186777220545610120709639892134449830665997715281940963297688861859037342461159276414933581239296064836432516763637141792816216974984349854006639899690176206857806767727053529035686928437176355492693417909899014432006512699533692521222248766184729181002509538111052158911254648850597987432471854055424
n = 18673976251335714476651394746499028113350224827648164334202987008038866750087651159656460363805650242579794802114819143058120476050272269676633677076385298863335666743508657148355537503320334423964478669547862048745388982570611276920575419903287594592604755888877966226587303816797977477875627765127667655069773076984497759230357272531161877298947004088021634961675381175234887420880583589643379281508985464253068469265371861887465940034266550475952405029099230256217994666983119524366143972788059755695324011389697559856564700518634829573248166083368742836213066209179209866459667310329794061135148197827371154401457
hint1 = 11366254007152589943518627583133256974537458716572137555165842306503166929977892900449448820433226457372162447047015369587723694789344872818804838088761773862185496980064650557766376859594011356728486009486008570119870273885945015520184876402482653049201984090267342781068825840293910886528379943008291807364157914918673618925141302586606321433398097897407938739760928222876461616544318211736025644700017455987969327050514136866673849232940121656644970801040367860611689452111182341031542986235741027198400665783777135706541143517282580089300702844364548658111475409322676811612758368904014652210190695250821451025332
P.<x,y>=PolynomialRing(Zmod(n))
f = (a_high+x)^3-3*(a_high+x)*(b_high+y)^2-hint1
a_low, b_low = small_roots(f, [2^128, 2^128], 3)[0]
print("a =", a_high + a_low)
print("b =", b_high + b_low)
```

#### `solve-hash101-part2.py` (Decrypt Flag)

```python
import hashlib
from Crypto.Cipher import ChaCha20
a = 9245771018720220165473157258175831420845484046990577190296029604996039184849924744238787339787096796382850266844371448691375170396739491301451548991057032485978061144056260933752650980783771487344689316401102847985381621048521201687177603399044498048732688462040589607869984341015544647397642092122769568708297556825246074288582430980733145683273350366571896960594430727649100079655830025058633724307540529672811566836398624593727396066740314639545029222687337384717592445245722536069434136020157395788948993000390733755319302103392189475532183523915862334850604599798634272974033997957722852339644786524103223538505
b = 8347635539592661235359577950860151375883964148441684625020802052680277442439812780330120330085363714762855342232831950915319740418302743720208454337743927246468200856158081923166989832989086672997741730659482257489996283828553436914665779494607346634534503720771705435695354568128843631458940027136419501885422264693186777220545610120709639892134449830665997715281940963297688861859037342461159276414933581239296064836432516763637141792816216974984349854006639899690176206857806767727053529035686928437176355492693417909899014432006512699533692521222248766184729181002509538111131676849151245536915401423323930829120
enc = b'Ts\xfe\x11\xb4\xdc?-\\_n\xdb \xbeM\xb8\x8a\xef\x83\xbd5\xfc\xccv&>\x87]D\xd7\xf8\xbbsg;\x16\xce\xcdS\x07H\xf7\xc7D\xef5\x14z\x98\xd2'
key = hashlib.sha256(str(a + b).encode()).digest()
nonce = b'Pr3d1ctmyxjj'
cipher = ChaCha20.new(key=key, nonce=nonce)
flag = cipher.decrypt(enc)
print(f"flag = {flag}")
```

### 🧠 Solution

We recover `m.re` and `m.im` to decrypt the flag:

1. **Setup**:

   - `m = Complex(m.re, m.im)`, `c = m^3 mod n`.
   - `mh` provides high bits of `m.re`, `m.im`.
   - Let `m.re = a_high + a_low`, `m.im = b_high + b_low`, `a_low, b_low < 2^128`.

2. **Polynomial**:

   - From `c.re`: \[ (a_high + x)^3 - 3 \\cdot (a_high + x) \\cdot (b_high + y)^2 - c.re = 0 \\mod n \]

3. **Coppersmith’s Method**:

   - Use `small_roots` to find `x, y < 2^128`.
   - Compute `m.re = a_high + a_low`, `m.im = b_high + b_low`.

4. **Decrypt**:

   - Key: `sha256(str(m.re + m.im))`.
   - Decrypt with ChaCha20.

**Flag**: `Securinets{h4sh3d_w1th_l0v3_and_0ff_by_0ne_err0rs}`

> **💡 Insight**: Coppersmith’s method exploits small `a_low, b_low`.

---

##  Challenge 5: ezMATH

###  Overview

**ezMATH** is an RSA challenge with:

- `n = p * q`, `e = 65537`.
- `c`: Encrypted flag.
- `hint = (2024 * p + 2025)^q mod n`.

### 📜 Provided Code

#### `ezMATH.py` (Generation)

```python
import libnum
from Crypto.Util.number import *

flag = "Securinets{**************}"
m = libnum.s2n(flag)
e = 65537
p = getPrime(1024)
q = getPrime(1024)
n = p * q
c = pow(m, e, n)
hint = pow(2024 * p + 2025, q, n)
print(f'n={n}')
print(f'c={c}')
print(f'hint={hint}')
```

#### `solve-ezMATH.py` (Solution)

```python
from Crypto.Util.number import *
n = 26496293393133904275617932586880403993530457555055576424526005160726735779818042733978670503571754372958919378304190479786594370088700918228062884856974869488870613256848937726869866711753323281549294303858741054476792769383014268272768921136086653616777218246393258349343645327759706610799151123274964758155772331364482601007193004712303866408907698946533994226867010588656673633044527882424575926999834152986892900713977932264003225248894379162903101983684014604517418280761851960688318854611168143752982508109119478816163067382250441260570756767414183749742690487331854542872207449313975039544969176676665407958319
c = 3360207033683588272694031077544334464808855778032572387679463556702847966884569897252759792629628998536597491919752452397610650291048251371323025380919048837893128399031077342059958847461225240382037929405794581426177116424035741189869537762780985133026215175734112489057734939993220198019345098942850479307330589517418218573003896187531533241015914395277640220928078414130073050537473462802912311045803937402312435045096877017052685442807942809236046488610962671392985546437742826721982532555349213751939951445579073205148050209273967571446834093173777505653600832057504025684549372907718404559391943522770741777809
hint = 17278727602055868817578311400780142902886864342556194174817267495993931970664438361669654322942319629930794269238533139041341463426584401478086008684655161722282090473621792258414917773812735786337043269310520444463599591989005199868225435798015186529483558486086878702455160616445656876376851093035216224898577288572910631185190689834621141390311709471913430603935553626649296606508160845993550055099604350868918482833496073786268921103055654285086577635894946229983997928194823375927798109604281887025306322935965674179371064816032196318926349142851964945860443949742918105324467310929342704644841898860603501454386
e = 65537
p = GCD(n, hint - pow(2025, n, n))
print(long_to_bytes(pow(c, inverse(e, (p-1)*(n//p-1)), n)))
```

### 🧠 Solution

1. **Analyze Hint**:

   - `hint = (2024 \cdot p + 2025)^q mod n`.
   - Compute: \[ hint - 2025^q \\mod n \]
   - Since `(a + b)^q \equiv a^q + b^q \mod q`: \[ (2024 \\cdot p + 2025)^q \\equiv 2025^q \\mod q \] So `q` divides `hint - pow(2025, n, n)`.

2. **Factor** `n`:

   - `p = GCD(n, hint - pow(2025, n, n))`.
   - `q = n // p`.

3. **Decrypt**:

   - `phi = (p-1)(q-1)`, `d = inverse(e, phi)`.
   - `flag = long_to_bytes(pow(c, d, n))`.

**Flag**: `Securinets{n0_m0r3_m4th_plz_just_g1v3_m3_th3_fl4g}`

> **💡 Insight**: The hint embeds `q` via modular arithmetic.

---

##  Challenge 6: QUANTUM-BB84

###  Overview

**QUANTUM-BB84** simulates the BB84 quantum key distribution protocol. We’re given:

- `qubits`: 100,000 qubits encoded as complex numbers.
- `bob_bases`: Bob’s measurement bases (`+` or `x`).
- `ciphertext`: Base64-encoded XOR-encrypted flag using a shared key.
- A fixed random seed (`999999999`).

We need to recover the shared key and decrypt the flag.

### 📜 Provided Code

#### `QUANTUM-BB84.py` (Generation)

```python
import math, random, base64, json, yaml

random.seed(999999999)
NUM_QUBITS = 100000
alice_bits = [random.randrange(2) for _ in range(NUM_QUBITS)]
alice_bases = [random.choice(['+','x']) for _ in range(NUM_QUBITS)]
qubits = []
for bit, base in zip(alice_bits, alice_bases):
    if base == '+':
        if bit == 0:
            qubit = {'real': 0.0, 'imag': 1.0}
        else:
            qubit = {'real': 1.0, 'imag': 0.0}
    else:
        amp = 1/math.sqrt(2)
        if bit == 0:
            qubit = {'real': amp, 'imag': amp}
        else:
            qubit = {'real': amp, 'imag': -amp}
    qubits.append(qubit)
bob_bases = [random.choice(['+','x']) for _ in range(NUM_QUBITS)]
bob_bits = []
for i in range(NUM_QUBITS):
    if bob_bases[i] == alice_bases[i]:
        bob_bits.append(alice_bits[i])
    else:
        bob_bits.append(random.randrange(2))
shared_key_bits = [alice_bits[i] for i in range(NUM_QUBITS)
                   if bob_bases[i] == alice_bases[i]]
flag = b"Securinets{QKD_zzzzzzzzzzzzzzzzzzMrx0rd}"
flag_bits = []
for byte in flag:
    for j in range(8):
        flag_bits.append((byte >> (7-j)) & 1)
if len(shared_key_bits) < len(flag_bits):
    shared_key_bits = (shared_key_bits * (len(flag_bits) // len(shared_key_bits) + 1))[:len(flag_bits)]
cipher_bits = [flag_bits[i] ^ shared_key_bits[i] for i in range(len(flag_bits))]
cipher_bytes = []
for i in range(0, len(cipher_bits), 8):
    byte = 0
    for b in cipher_bits[i:i+8]:
        byte = (byte << 1) | b
    cipher_bytes.append(byte)
ciphertext_b64 = base64.b64encode(bytes(cipher_bytes)).decode()
public_data = {
    'qubits': qubits,
    'bob_bases': ''.join(bob_bases),
    'ciphertext': ciphertext_b64
}
with open("challenge.yml", "w") as f:
    yaml.dump(public_data, f, default_flow_style=False)
```

#### `solver-BB84.py` (Solution)

```python
import yaml
import base64
import math

with open("challenge.yml", "r") as f:
    data = yaml.safe_load(f)
qubits = data['qubits']
bob_bases = data['bob_bases']
ciphertext_b64 = data['ciphertext']
ciphertext_bytes = base64.b64decode(ciphertext_b64)
shared_key_bits = []
for i, base in enumerate(bob_bases):
    qubit = qubits[i]
    real = qubit['real']
    imag = qubit['imag']
    if base == '+':
        if imag == 1.0:
            alice_bit = 0
        elif real == 1.0:
            alice_bit = 1
        else:
            continue
    elif base == 'x':
        if math.isclose(real, 1 / math.sqrt(2)) and math.isclose(imag, 1 / math.sqrt(2)):
            alice_bit = 0
        elif math.isclose(real, 1 / math.sqrt(2)) and math.isclose(imag, -1 / math.sqrt(2)):
            alice_bit = 1
        else:
            continue
    shared_key_bits.append(alice_bit)
ciphertext_bits = []
for byte in ciphertext_bytes:
    for i in range(8):
        ciphertext_bits.append((byte >> (7 - i)) & 1)
if len(shared_key_bits) < len(ciphertext_bits):
    shared_key_bits = (shared_key_bits * (len(ciphertext_bits) // len(shared_key_bits) + 1))[:len(ciphertext_bits)]
flag_bits = [ciphertext_bits[i] ^ shared_key_bits[i] for i in range(len(ciphertext_bits))]
flag_bytes = []
for i in range(0, len(flag_bits), 8):
    byte = 0
    for b in flag_bits[i:i+8]:
        byte = (byte << 1) | b
    flag_bytes.append(byte)
flag = bytes(flag_bytes).decode()
print(f"Flag: {flag}")
```

### 🧠 Solution

**QUANTUM-BB84** simulates the BB84 protocol but is vulnerable due to a fixed random seed.

1. **Understand BB84**:

   - **Alice** generates `alice_bits` (0 or 1) and `alice_bases` (`+` or `x`).
   - For each bit and basis:
     - `+` basis: `0 = |0⟩ = (0, 1)`, `1 = |1⟩ = (1, 0)`.
     - `x` basis: `0 = |+⟩ = (1/√2, 1/√2)`, `1 = |-⟩ = (1/√2, -1/√2)`.
   - **Bob** measures in random bases (`bob_bases`).
   - If `alice_bases[i] == bob_bases[i]`, Bob gets `alice_bits[i]`; otherwise, he gets a random bit.
   - The shared key is `alice_bits[i]` where bases match.

2. **Vulnerability**:

   - The script uses `random.seed(999999999)`, making all random choices (bits, bases) deterministic.
   - We’re given `qubits` (Alice’s quantum states) and `bob_bases`.

3. **Recover Shared Key**:

   - For each qubit and Bob’s basis:
     - If `base == '+'`:
       - `(0, 1)` → `alice_bit = 0`.
       - `(1, 0)` → `alice_bit = 1`.
     - If `base == 'x'`:
       - `(1/√2, 1/√2)` → `alice_bit = 0`.
       - `(1/√2, -1/√2)` → `alice_bit = 1`.
   - When `alice_bases[i] == bob_bases[i]`, `alice_bit` is part of the shared key.
   - The solver checks qubit values to deduce `alice_bits`.

4. **Decrypt the Flag**:

   - Convert `ciphertext_b64` to bits.
   - Extend `shared_key_bits` by repetition if needed.
   - XOR `ciphertext_bits` with `shared_key_bits` to get `flag_bits`.
   - Convert bits to bytes.

5. **Run the Script**:

   ```bash
   python solver-BB84.py
   ```

   **Flag**: `Securinets{QKD_zzzzzzzzzzzzzzzzzzMrx0rd}`

**Why it Works**:

- The fixed seed makes `alice_bits` and `alice_bases` reproducible.
- `qubits` encode `alice_bits` directly, and `bob_bases` let us extract the shared key where bases match.

> **💡 Insight**: The fixed random seed undermines BB84’s security, allowing us to reconstruct the key.

---

## 🎯 Conclusion

These CyberTek challenges cover a wide range of cryptographic concepts:

- **ezRSA+**: Non-standard RSA with a gift.
- **syb3lik**: Weak elliptic curve RNG.
- **ezRSA**: Linear algebra for RSA factoring.
- **hash101**: Coppersmith’s method for complex RSA.
- **ezMATH**: GCD-based RSA factoring.
- **QUANTUM-BB84**: Exploiting a deterministic BB84 implementation.

Each puzzle is educational and engaging, showcasing creative vulnerabilities.

**Flags**:

- **ezRSA+**: `Securinets{diff1cult_rsa_1s_e@sy_xxxxxxxxxxxxxxxxxx}`
- **syb3lik**: Securinets{D0ubl2_Tr0ubl201574944849498474}
- **ezRSA**: `Securinets{~:L1n34r_Pr1m3E_114!!!!}`
- **hash101**: `Securinets{h4sh3d_w1th_l0v3_and_0ff_by_0ne_err0rs}`
- **ezMATH**: `Securinets{n0_m0r3_m4th_plz_just_g1v3_m3_th3_fl4g}`
- **QUANTUM-BB84**: `Securinets{QKD_zzzzzzzzzzzzzzzzzzMrx0rd}`

---

*Author CyberTek CTF: MRx0rd 🕷️🛡️*
