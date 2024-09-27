---
date: "2024-07-01"
title: 2024UIUCTF
---
## Without a Trace

```python
import numpy as np
from Crypto.Util.number import bytes_to_long
from itertools import permutations
from SECRET import FLAG


def inputs():
    print("[WAT] Define diag(u1, u2, u3. u4, u5)")
    M = [
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]
    for i in range(5):
        try:
            M[i][i] = int(input(f"[WAT] u{i + 1} = "))
        except:
            return None
    return M

def handler(signum, frame):
    raise Exception("[WAT] You're trying too hard, try something simpler")

def check(M):
    def sign(sigma):
        l = 0
        for i in range(5):
            for j in range(i + 1, 5):
                if sigma[i] > sigma[j]:
                    l += 1
        return (-1)**l

    res = 0
    for sigma in permutations([0,1,2,3,4]):
        curr = 1
        for i in range(5):
            curr *= M[sigma[i]][i]
        res += sign(sigma) * curr
    return res

def fun(M):
    f = [bytes_to_long(bytes(FLAG[5*i:5*(i+1)], 'utf-8')) for i in range(5)]
    F = [
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]
    for i in range(5):
        F[i][i] = f[i]

    try:
        R = np.matmul(F, M)
        return np.trace(R)

    except:
        print("[WAT] You're trying too hard, try something simpler")
        return None

def main():
    print("[WAT] Welcome")
    M = inputs()
    if M is None:
        print("[WAT] You tried something weird...")
        return
    elif check(M) == 0:
        print("[WAT] It's not going to be that easy...")
        return

    res = fun(M)
    if res == None:
        print("[WAT] You tried something weird...")
        return
    print(f"[WAT] Have fun: {res}")

if __name__ == "__main__":
    main()

```

$$
M=\left[\begin{matrix}
u_1&0&0&0&0\\0&u_2&0&0&0\\0&0&u_3&0&0\\0&0&0&u_4&0\\0&0&0&0&u_5
\end{matrix}\right]
$$

数据自己输入，最简单思路就是用给的`server.py`跑一遍打印出来找找规律
$$
R=\left[\begin{matrix}
f_1&0&0&0&0\\0&f_2&0&0&0\\0&0&f_3&0&0\\0&0&0&f_4&0\\0&0&0&0&f_5
\end{matrix}\right]*M=\left[\begin{matrix}
f_1u_1&0&0&0&0\\0&f_2u_2&0&0&0\\0&0&f_3u_3&0&0\\0&0&0&f_4u_4&0\\0&0&0&0&f_5u_5
\end{matrix}\right]
$$
返回的是`np.trace(R)`，没见过的函数，百度下发现是迹(对角元素之和)，传入不同数据相减就能得到明文，传入`1,1,1,1,1`得到`s`，传入`2,1,1,1,1`得到$a_1$，传入`1,2,1,1,1`得到$a_2$以此类推。
$$
s=f_1+f_2+f_3+f_4+f_5\\
a_1=2f_1+f_2+f_3+f_4+f_5
$$

```python
from Crypto.Util.number import *
s = 2000128101369
a = [2504408575853, 2440285994541, 2426159182680, 2163980646766, 2465934208374]
print(b''.join(long_to_bytes(i-s) for i in a))
```

## Determined

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from itertools import permutations
from SECRET import FLAG, p, q, r



def inputs():
    print("[DET] First things first, gimme some numbers:")
    M = [
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0],
    ]
    try:
        M[0][0] = p
        M[0][2] = int(input("[DET] M[0][2] = "))
        M[0][4] = int(input("[DET] M[0][4] = "))

        M[1][1] = int(input("[DET] M[1][1] = "))
        M[1][3] = int(input("[DET] M[1][3] = "))

        M[2][0] = int(input("[DET] M[2][0] = "))
        M[2][2] = int(input("[DET] M[2][2] = "))
        M[2][4] = int(input("[DET] M[2][4] = "))

        M[3][1] = q
        M[3][3] = r

        M[4][0] = int(input("[DET] M[4][0] = "))
        M[4][2] = int(input("[DET] M[4][2] = "))
    except:
        return None
    return M

def handler(signum, frame):
    raise Exception("[DET] You're trying too hard, try something simpler")

def fun(M):
    def sign(sigma):
        l = 0
        for i in range(5):
            for j in range(i + 1, 5):
                if sigma[i] > sigma[j]:
                    l += 1
        return (-1)**l

    res = 0
    for sigma in permutations([0,1,2,3,4]):
        curr = 1
        for i in range(5):
            curr *= M[sigma[i]][i]
        res += sign(sigma) * curr
    return res

def main():
    print("[DET] Welcome")
    M = inputs()
    if M is None:
        print("[DET] You tried something weird...")
        return

    res = fun(M)
    print(f"[DET] Have fun: {res}")

if __name__ == "__main__":
    main()
```

$$
\left[\begin{matrix}
p&0&a_1&0&a_2\\0&a_3&0&a_4&0\\a_5&0&a_6&0&a_7\\0&q&0&r&0\\a_8&0&a_9&0&0
\end{matrix}\right]
$$

因为`fun`函数给了我们，自然可以打印出`sigma`和`sign(sigma)`查看函数作用，打印出来`1`和`-1`交替出现，代入几组`curr *= M[sigma[i]][i]`查看对应关系，这不就是求`det`的过程，那么就简单了，取所有数相等时
$$
det=a_7*a_9*(p-a_8)*(q*a_4-r*a_3)
$$
然后用`1`和`2`代入取`gcd`能得出`q-r`

```python
from Crypto.Util.number import *
t1 = 69143703864818353130371867063903344721913499237213762852365448402106351546379534901008421404055139746270928626550203483668654060066917995961156948563756758160310602854329852071039981874388564191274850542349182490083881348633205451737697677971069061869428981062350490771144358405734467651517359001029442068348
t2 = 553149630918546825042974936511226757775307993897710102818923587216850812371036279208067371232441117970167429012401627869349232480535343967689255588510054021604308093581560614102191724248085984053275943784896193396205970938993896506348189205807658060722666569533551014249382616932774169066997857895728946410896
p_r = GCD(t1, t2)	# p-1是偶数,故求出来不是q-r,是q-r的偶数倍,题目给的数据刚好是2倍
p = (t1//(p_r // 2)) + 1

n = 158794636700752922781275926476194117856757725604680390949164778150869764326023702391967976086363365534718230514141547968577753309521188288428236024251993839560087229636799779157903650823700424848036276986652311165197569877428810358366358203174595667453056843209344115949077094799081260298678936223331932826351
e = 65535
c = 72186625991702159773441286864850566837138114624570350089877959520356759693054091827950124758916323653021925443200239303328819702117245200182521971965172749321771266746783797202515535351816124885833031875091162736190721470393029924557370228547165074694258453101355875242872797209141366404264775972151904835111
print(long_to_bytes(pow(c, inverse(e, p-1), p)))
```



## Naptime

```python
from random import randint
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import numpy as np

def get_b(n):
    b = []
    b.append(randint(2**(n-1), 2**n))
    for i in range(n - 1):
        lb = sum(b)
        found = False
        while not found:
            num = randint(max(2**(n + i), lb + 1), 2**(n + i + 1))
            if num > lb:
                found = True
                b.append(num)

    return b

def get_MW(b):
    lb = sum(b)
    M = randint(lb + 1, 2*lb)
    W = getPrime(int(1.5*len(b)))

    return M, W

def get_a(b, M, W):
    a_ = []
    for num in b:
        a_.append(num * W % M)
    pi = np.random.permutation(list(i for i in range(len(b)))).tolist()
    a = [a_[pi[i]] for i in range(len(b))]
    return a, pi


def enc(flag, a, n):
    bitstrings = []
    for c in flag:
        # c -> int -> 8-bit binary string
        bitstrings.append(bin(ord(c))[2:].zfill(8))
    ct = []
    for bits in bitstrings:
        curr = 0
        for i, b in enumerate(bits):
            if b == "1":
                curr += a[i]
        ct.append(curr)

    return ct

def dec(ct, a, b, pi, M, W, n):
    # construct inverse permuation to pi
    pii = np.argsort(pi).tolist()
    m = ""
    U = pow(W, -1, M)
    ct = [c * U % M for c in ct]
    for c in ct:
        # find b_pi(j)
        diff = 0
        bits = ["0" for _ in range(n)]
        for i in reversed(range(n)):
            if c - diff > sum(b[:i]):
                diff += b[i]
                bits[pii[i]] = "1"
        # convert bits to character
        m += chr(int("".join(bits), base=2))

    return m


def main():
    flag = 'uiuctf{I_DID_NOT_LEAVE_THE_FLAG_THIS_TIME}'

    # generate cryptosystem
    n = 8
    b = get_b(n)
    M, W = get_MW(b)
    a, pi = get_a(b, M, W)

    # encrypt
    ct = enc(flag, a, n)

    # public information
    print(f"{a =  }")
    print(f"{ct = }")

    # decrypt
    res = dec(ct, a, b, pi, M, W, n)

if __name__ == "__main__":
    main()
"""
a =  [66128, 61158, 36912, 65196, 15611, 45292, 84119, 65338]
ct = [273896, 179019, 273896, 247527, 208558, 227481, 328334, 179019, 336714, 292819, 102108, 208558, 336714, 312723, 158973, 208700, 208700, 163266, 244215, 336714, 312723, 102108, 336714, 142107, 336714, 167446, 251565, 227481, 296857, 336714, 208558, 113681, 251565, 336714, 227481, 158973, 147400, 292819, 289507]"""
```

单看了`enc`函数就可以得出答案，将`flag`每个字符的`ascii`用二进制表示，长度为`8`刚好和`a`数组长度相等，依次对应如果是`1`则相加，`0`则略过，那么直接爆破即可，`8`个数字每个`2`种情况，`2**8`即可，这样便可得到单字符；再对`ct`数组里每个用相同的思想，组合在一起即可

```python
if __name__ == "__main__":
    # main()
    a = [66128, 61158, 36912, 65196, 15611, 45292, 84119, 65338]
    ct = [273896, 179019, 273896, 247527, 208558, 227481, 328334, 179019, 336714, 292819, 102108, 208558, 336714,
          312723, 158973, 208700, 208700, 163266, 244215, 336714, 312723, 102108, 336714, 142107, 336714, 167446,
          251565, 227481, 296857, 336714, 208558, 113681, 251565, 336714, 227481, 158973, 147400, 292819, 289507]
    for t in ct:
        for i in range(256):
            curr = 0
            for j, b in enumerate(bin(i)[2:].zfill(8)):
                if b == "1":
                    curr += a[j]
            if curr == t:
                print(chr(i), end='')
```

## Snore Signatures

```python
#!/usr/bin/env python3

from Crypto.Util.number import isPrime, getPrime, long_to_bytes, bytes_to_long
from Crypto.Random.random import getrandbits, randint
from Crypto.Hash import SHA512
from hashlib import sha512
LOOP_LIMIT = 2000


def hash(val, bits=1024):
    output = 0
    for i in range((bits//512) + 1):
        h = SHA512.new()
        h.update(long_to_bytes(val) + long_to_bytes(i))
        # print(h.hexdigest())
        output = int(h.hexdigest(), 16) << (512 * i) ^ output
    return output


def gen_snore_group(N=512):
    q = getPrime(N)
    for _ in range(LOOP_LIMIT):
        X = getrandbits(2*N)
        p = X - X % (2 * q) + 1
        if isPrime(p):
            break
    else:
        raise Exception("Failed to generate group")

    r = (p - 1) // q

    for _ in range(LOOP_LIMIT):
        h = randint(2, p - 1)
        if pow(h, r, p) != 1:
            break
    else:
        raise Exception("Failed to generate group")

    g = pow(h, r, p)

    return (p, q, g)


def snore_gen(p, q, g, N=512):
    x = randint(1, q - 1)
    y = pow(g, -x, p)
    return (x, y)


def snore_sign(p, q, g, x, m):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    # print(sha512(long_to_bytes(r+m)+long_to_bytes(0)).hexdigest())
    e = hash((r + m) % p) % q

    s = (k + x * e) % q
    return (s, e)


def snore_verify(p, q, g, y, m, s, e):
    if not (0 < s < q):
        return False

    rv = (pow(g, s, p) * pow(y, e, p)) % p
    ev = hash((rv + m) % p) % q

    return ev == e


def main():
    p, q, g = gen_snore_group()
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")

    queries = []
    for _ in range(10):
        x, y = snore_gen(p, q, g)
        print(f"y = {y}")

        print('you get one query to the oracle')

        m = int(input("m = "))
        queries.append(m)
        s, e = snore_sign(p, q, g, x, m)
        print(f"s = {s}")
        print(f"e = {e}")

        print('can you forge a signature?')
        m = int(input("m = "))
        s = int(input("s = "))
        # you can't change e >:)
        if m in queries:
            print('nope')
            return
        if not snore_verify(p, q, g, y, m, s, e):
            print('invalid signature!')
            return
        queries.append(m)
        print('correct signature!')

    print('you win!')
    print(open('flag.txt').read())

if __name__ == "__main__":
    main()

```

$$
r\equiv g^k\mod p\\
e\equiv hash((r+m)\%p)\mod q\\
s\equiv k+x*e\mod q\\
\\
rv\equiv g^s*y^e\equiv g^k*g^{xe}*g^{-xe}\equiv g^k\equiv r\mod p \\
ev\equiv hash((rv+m))\%p\mod q
$$

加解密的过程如此，确实成立，`sha512`不像`md5`一样可以进行碰撞，我们注意到`hash`函数用的是`r+m`那么只要满足倍数关系时放入的数字在模`p`下相等，加密出来肯定是一样的，这样可以构成不同的`m`
$$
(r+m+p)\% p=(r+m)\%p
$$

```python
from pwn import *
nc = remote('snore-signatures.chal.uiuc.tf', 1337, ssl=True)
li = nc.recv().strip().split(b'\n')
for i in li:
    exec(i)


for i in range(10):
    nc.recvuntil(b'you get one query to the oracle')
    print(nc.recv())
    nc.sendline(str(p+i).encode())
    s = nc.recv().split()[2]
    nc.sendline(str(i).encode())
    nc.sendline(s)
    print(nc.recvline())

nc.interactive()

```



## Groups

```python
from random import randint
from math import gcd, log
import time
from Crypto.Util.number import *


def check(n, iterations=50):
    if isPrime(n):
        return False

    i = 0
    while i < iterations:
        a = randint(2, n - 1)
        if gcd(a, n) == 1:
            i += 1
            if pow(a, n - 1, n) != 1:
                return False
    return True


def generate_challenge(c):
    a = randint(2, c - 1)
    while gcd(a, c) != 1:
        a = randint(2, c - 1)
    k = randint(2, c - 1)
    return (a, pow(a, k, c))


def get_flag():
    with open('flag.txt', 'r') as f:
        return f.read()

if __name__ == '__main__':
    c = int(input('c = '))

    if log(c, 2) < 512:
        print(f'c must be least 512 bits large.')
    elif not check(c):
        print(f'No cheating!')
    else:
        a, b = generate_challenge(c)
        print(f'a = {a}')
        print(f'a^k = {b} (mod c)')
        
        k = int(input('k = '))

        if pow(a, k, c) == b:
            print(get_flag())
        else:
            print('Wrong k')
        

```

既非指数又要满足$a^{n-1}\equiv1\mod n$，真是个奇怪的要求，还好题目给了提示`Carmichael numbers`（[卡迈克尔数](https://www.wikiwand.com/zh-cn/%E5%8D%A1%E9%82%81%E5%85%8B%E7%88%BE%E6%95%B8)），既要满足光滑性，又要是卡迈克尔数，程序跑了一个多小时终于出来了一组（感谢[石氏是时试师傅](https://blog.csdn.net/weixin_52640415/article/details/140190920)指出`p_minus_one`函数的问题，判断`n//6+1`是质数确实是无关条件，只会让数据更难生成，所以比赛时才跑了一个多小时）

```python
from random import randint
from math import gcd, log
import time
from random import choice
from Crypto.Util.number import *


def check(n, iterations=50):
    if isPrime(n):
        return False

    i = 0
    while i < iterations:
        a = randint(2, n - 1)
        if gcd(a, n) == 1:
            i += 1
            if pow(a, n - 1, n) != 1:
                return False
    return True

def p_minus_one(bits):
    while True:
        n = 6
        while n.bit_length() < bits:
            n *= choice(sieve_base)
        if n % 6 == 0:
            # if isPrime(n//6+1):
            if isPrime(n+1):
                return n//6


while True:
    k = p_minus_one(172)
    # print(k)
    if isPrime(18*k+1):
        if isPrime(12*k+1):
            temp = (6*k+1)*(18*k+1)*(12*k+1)
            print(k, check(temp), temp)
            break
        elif isPrime(54*k**2 + 12*k + 1):
            temp = (6 * k + 1) * (18 * k + 1) * (54*k**2 + 12*k + 1)
            print(k, check(temp), temp)
            break


# 6901434485173751316563547551309541455058839927966004886 True 426013253429942512338128950387935694151531171261217142574298721508776683346877722021197695005685230550878337707065141465365752980847132936665106372162372794408712041289
```

然后就是用`sage`的`discrete_log`求离散对数，发现用第二组数据代入$g^{x}$刚好与`c`相等

```python
g = 162712147053983529589941603520587292910652437327235076245481396441063599676375258262225388397911669358409989909710123370044848656649806438009689223352999844570370080471
c = 57470451280649117089429433913713972622901341056121419945017217793954939619509771193589950881703201287374234979087280243651813803882371734925444169713668103966201461656
k = 6901434485173751316563547551309541455058839927966004886
p = 6*k+1
q = 12*k+1
r = 18*k+1
discrete_log(mod(c, p), mod(g, p))	# 110791277153326299669714579266547703774503985112536606
discrete_log(mod(c, q), mod(g, q))	# 62223701643717088148741642541052420799304063336806580580
discrete_log(mod(c, r), mod(g, r))	# 110791277153326299669714579266547703774503985112536606
```

## *Key in a Haystack

```python
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

from hashlib import md5
from math import prod
import sys

from secret import flag

key = getPrime(40)
haystack = [ getPrime(1024) for _ in range(300) ]
key_in_haystack = key * prod(haystack)

enc_flag = AES.new(
	key = md5(b"%d" % key).digest(),
	mode = AES.MODE_ECB
).encrypt(pad(flag, 16))

sys.set_int_max_str_digits(0)

print(f"enc_flag: {enc_flag.hex()}")
print(f"haystack: {key_in_haystack}")

exit(0)
```

一堆大质数里面混入了个小质数，需要将这个小质数解出，虽然`yafu`可以运作，但`yafu`没有调试情况，需要算出所有因子后才能输出，这条路明显行不通；等比赛结束后看题解才意识到`key`非常小，有可能是`p-1`光滑，而`p-1`光滑可以用`Pollard`算出，虽然也得跑个十分钟；但是得到`n`中的`key`不一定是光滑的，概率是5%，多尝试几组就有可能可以得到。（ps：`discord`里出题人说用`ecm`指令解决，但这个工具着实不会用，教程也没找到）

```python
def pollards_p_minus_1_sage(n, a=2, B=2**13):
    b = factorial(B)
    tmp1 = n
    tmp2 = power_mod(a, b, n) - 1
    gcd_value = gcd(tmp1, tmp2)
    return gcd_value
n = open('D:/ctf/pcat.txt').read()
pollards_p_minus_1_sage(int(n))	# 1028327996977
```

跑了大概六组左右，得到`key`之后就是常规解密

```python
from Crypto.Cipher import AES
from hashlib import md5
from Crypto.Util.number import *
key = 1028327996977
aes = AES.new(md5(str(key).encode()).digest(), AES.MODE_ECB)

c = '37920e32117dc9b632581746334457cac311b52c666c76282c03fd70f4fde84c0c07e76ee7d4f5f3a4ac172561fb90a4'
c = long_to_bytes(int(c, 16))

print(aes.decrypt(c))
```

