---
date: "2024-09-22"
title: 2024ASISCTF
---

# Crypto

## Ataa

```python
#!/usr/bin/env python3

import sys
from Crypto.Util.number import *
from string import *
from random import *
from math import gcd
from secret import p, flag
	
def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc(): 
	return sys.stdin.buffer.readline()

def check(u, v, w, x, y, z, k, p):
	if len(set([u, v, w, x, y, z])) == 6:
		if all(map(lambda t: t % p != 0, [u, v, w, x, y, z, k])):
			if gcd(u, v, w, x, y, z, k, p) == 1:
				if (pow(u, k, p) + v * w * x * y * z) % p + (pow(v, k, p) + u * w * x * y * z) % p + \
				   (pow(w, k, p) + v * u * x * y * z) % p + (pow(x, k, p) + v * w * u * y * z) % p + \
				   (pow(y, k, p) + v * w * x * u * z) % p + (pow(z, k, p) + v * w * x * y * u) % p == 0:
					return True
	return False

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:: Welcome to ATAA task! Your mission is pass only one level! ::.", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	nbit, _b = 128, False
	pr(border, f'p = {p}')
	pr(border, f"Please provide your desired {nbit}-integers:")
	inp = sc().decode()
	try:
		u, v, w, x, y, z, k = [int(_) for _ in inp.split(',')]
		if u.bit_length() == v.bit_length() == w.bit_length() == x.bit_length() == \
		   y.bit_length() == z.bit_length() == nbit and k.bit_length() >= nbit:
			_b = True
	except:
		die(border, f"The input you provided is not valid!")
	if _b:
		if check(u, v, w, x, y, z, k, p):
			die(border, f'Congrats, you got the flag: {flag}')
		else:
			die(border, f'The input integer is not correct! Bye!!')
	else:
		die(border, f"Your input does not meet the requirements!!!")

if __name__ == '__main__':
	main()
```

$$
u^k+vwxyz\equiv0\mod p\\
v^k+uwxyz\equiv0\mod p\\
w^k+vuxyz\equiv0\mod p\\
x^k+vwuyz\equiv0\mod p\\
y^k+vwxuz\equiv0\mod p\\
z^k+vwxyu\equiv0\mod p
$$

总共有六个数据，而且还不能相同，如果能相同直接传入七个`k-1`即可，在这里卡住很久；但是两两可以一组，两个形成逆元的话可以把五元式子变成单变量，再放到sage里面解根。
$$
u^k+x\equiv0\mod p,\qquad u*x\equiv1\mod p\\
x\equiv -u^k\mod p\Rightarrow u^{k+1}+1\equiv0\mod p
$$
如果k很小不容易出答案，高次方的解数量才多嘛。然后对本身和其逆元判断位数并选出合适的三对，最后选出一组使check为0的k。

```python
from Crypto.Util.number import *

def check(u, v, w, x, y, z, k, p):
    return (pow(u, k, p) + v * w * x * y * z) % p + (pow(v, k, p) + u * w * x * y * z) % p + (
                pow(w, k, p) + v * u * x * y * z) % p + (pow(x, k, p) + v * w * u * y * z) % p + (
                pow(y, k, p) + v * w * x * u * z) % p + (pow(z, k, p) + v * w * x * y * u) % p

def solve():
    nc = remote('65.109.192.143', 13731)
    nc.recvuntil(b'p = ')
    p = eval(nc.recvline().strip())
    print(p)
    R.<x> = PolynomialRing(GF(p))
    f = x^210 + 1
    tmp = f.roots()
    tmp = [int(tmp[i][0]) for i in range(0, len(tmp), 2) if (int(tmp[i][0]).bit_length() == 128 or (int(tmp[i][0]) + int(p)).bit_length() == 128) and (int(tmp[i + 1][0]).bit_length() == 128 or (int(tmp[i + 1][0]) + int(p)).bit_length() == 128)]
    # print(tmp)
    if len(tmp)>=3:
        li = [tmp[0], tmp[1], tmp[2]]
        u, v, w = li
        x = inverse(u, p)
        y = inverse(v, p)
        z = inverse(w, p)
        li = [u, v, w, x, y, z]
        li = [i if i.bit_length() == 128 else i + p for i in li]
        u, v, w, x, y, z = li
        for i in li:
            nc.send(f"{i},".encode())
        for i in range(500):
            k = p + i
            # print(u.bit_length() == v.bit_length() == w.bit_length() == x.bit_length() == y.bit_length() == z.bit_length() == 128)
            if check(u, v, w, x, y, z, k, p) == 0:
                nc.sendline(f"{k}".encode())
                break
        nc.interactive()
    else:
        print('again')
        return 0
solve()
```

## Avini

```python
#!/usr/bin/env python3

import sys
from random import *
from Crypto.Util.number import *
from Crypto.PublicKey import ECC
from flag import flag

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc(): 
	return sys.stdin.buffer.readline()

def genon(nbit):
	R = list(range(1, nbit))
	shuffle(R)
	B = ['1'] + ['0'] * (nbit - 1)
	u = randint(nbit // 2 + 5, 2 * nbit // 3)
	for i in range(0, u):
		B[R[i]] = '1'
	return int(''.join(B), 2)

def is_genon(n, nbit):
	return n.bit_length() == nbit and bin(n)[2:].count('1') >= nbit // 2 + 1

def main():
	border = "┃"
	pr("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr("┃ Welcome to AVINI challenge! Here we can double your points on ECC! ┃")
	pr("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

	nbit = 256
	key = ECC.generate(curve='P-256')
	order = ECC._curves['NIST P-256'][2]
	Q = key.pointQ
	O = ECC.EccPoint(Q.x, Q.y, curve='p256').point_at_infinity()

	pr(border, f"Please provide your desired integer `n' or even the binary ")
	pr(border, f"representation of it, [D]ecimal or [B]inary?")
	
	ans = sc().decode().strip().lower()
	if ans == 'd':
		pr(border, "So send the integer n: ")
		_n = sc().decode()
		try:
			_n = int(_n)
		except:
			die(border, 'Your input is not integer!')
		if is_genon(_n, nbit):
			R, P, c = O, Q.copy(), 0
			for _b in bin(_n)[2:][::-1]:
				if _b == '1':
					R = R + P
					c += 1
				P = P.double()
				c += 1
				if 18 * c >= 19 * nbit:
					break
			if R == Q * _n and _n < order:
				die(border, f'Congrats, you got the flag: {flag}')
			else:
				die(border, f'The calculations failed! Sorry!!')
		else:
			die(border, 'Your integer does not satisfy the requirements!')
	elif ans == 'b':
		pr(border, "Now send the binary representation of n separated by comma: ")
		_B = sc().decode()
		try:
			_B = [int(_) for _ in _B.split(',')]
			_flag = all(abs(_) <= 1 for _ in _B) and len(_B) == nbit
		except:
			die(border, 'Your input is not corr3ct!')
		if _flag:
			R, P, c, i, _n = O, Q.copy(), 0, 0, 0
			for _b in _B[::-1]:
				if _b != 0:
					_n += 2 ** i * _b
					R += P if _b > 0 else -P
					c += 1
				P = P.double()
				c += 1
				i += 1
				if 71 * c >= 72 * nbit:
					break
			if _n.bit_length() == nbit and _n < order and R == Q * _n:
				die(border, f'Congrats, you got the flag: {flag}')
			else:
				die(border, f'The calculations failed! Sorry!!')
		else:
			die(border, f'Your binary representation does not satisfy the requirements!!')
	else:
		die(border, "Your choice is not correct, Goodbye!!")	

if __name__ == '__main__':
	main()
```

定义了随机点`Q`和无穷远点`O`，无论是`D`模式还是`B`模式，实际上是在算点乘，但`D`模式相较`B`模式多了`is_genon`的判断；`P`记录下基点`Q`，而`R`记录下点乘结果`_n*Q`，如果最后`R==Q*_n`则输出`flag`；不是哥们，这题有毛病吧，这不是很显然相等嘛，走`B`连`is_genon`绕过都不需要。

但是要注意存在如下退出语句，那么`1`的数量不能太多（更加证明走`D`行不通），不然退出后得到的`_n`必然从后面开始截取，无法与原`_n`相等。

```python
if 71 * c >= 72 * nbit:
	break
```

最简单就是传入1和255个0

```python
print(*([1]+[0]*255), sep=',')
```

## Clement

```python
#!/usr/bin/env python3

import time
from functools import wraps
from Crypto.Util.number import *
from signal import *
from secret import rapid_factoreal_check, flag

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc():
	return sys.stdin.buffer.readline()

class TimeoutError(Exception):
	pass

def exec_limit(mt):
	def decorator(func):
		@wraps(func)
		def wrapper(*args, **kwargs):
			def _handle_timeout(signum, frame):
				raise TimeoutError(f"Function execution time exceeded {mt} seconds.")
			old_handler = signal(SIGALRM, _handle_timeout)
			alarm(int(mt))
			try:
				result = func(*args, **kwargs)
			except TimeoutError:
				return False
			finally:
				signal(SIGALRM, old_handler)
			return result
		return wrapper
	return decorator

TIMEOUT = 3
@exec_limit(TIMEOUT)
def factoreal(n, k, b):
	if b: # When YOU have access to supercomputer!
		i, s = 1, 1
		while i < n + 1:
			s = (s * i) % k
			i += 1
		if (4 * s + n + 5) % k == 0:
			return True
		return False
	else: # Otherwise
		return rapid_factoreal_check(n)

def main():
	global secret, border
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, "Welcome to Clement Crypto Challenge, we have gained access to a   ", border)
	pr(border, "very powerful supercomputer with high processing capabilities. Try", border)
	pr(border, "to connect to the app running on this computer and find the flag. ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	b, c, nbit, STEP = False, 0, 64, 40
	for level in range(STEP):
		pr(border, f"Your are at level {level + 1} of {STEP}")
		pr(border, f"Please submit an {nbit}-integer:")
		_n = sc().decode()
		try:
			_n = int(_n)
			_k = _n**2 + 4*_n + 3
		except:
			die(border, 'Your input is not integer! Bye!!')
		if _n.bit_length() == nbit:
			try:
				_b = factoreal(_n, _k, b)
			except TimeoutError:
				pass
		else:
			die(border, f"Your input integer is NOT {nbit}-bit! Bye!!") 
		if _b:
			c += 1
			nbit = int(1.1 * nbit) + getRandomRange(1, 12)
			if c >= STEP:
				die(border, f'Congratulation! You got the flag: {flag}')
		else:
			die(border, "Wrong response! Start again. Bye!!") 

if __name__ == '__main__':
	main()
```

$$
k=n^2+4n+3\equiv(n+1)(n+3)\\
s=\prod_{i=1}^{n}i\mod k\\
4s+n+5\equiv0\mod k
$$

威尔逊定理和中国剩余定理的结合，如果`n+1`和`n+3`都是质数的话，那么就可以转化成威尔逊定理，实际上这样两个素数称为孪生素数(twin prime)
$$
(p-1)!\equiv -1\mod p
$$
再用中国剩余定理求出`s`，可以发现最后一定是0
$$
s=\begin{cases}-1\mod n+1\\
-1*(n+1)^{-1}*(n+2)^{-1}\mod n+3
\end{cases}
$$

```python
from Crypto.Util.number import *
from gmpy2 import next_prime
from sympy.ntheory.modular import crt

while True:
    a = getPrime(64)
    b = next_prime(a)
    if b-a == 2:
        print(a, b)
        break
n = a-1
k = n**2+4*n+3
s = crt([a, b], [-1, -1*inverse(n+1, b)*inverse(n+2, b)%b])[0]
print((4*s+n+5)%k)
```

最后就是漫长的等待过程，因为程序里有时间限制，只能通过打表，不然位数大时调用会超时，题目刚开始是40不过后面改了，次数变成19次，大小最坏情况下也就到1000左右。

```python
from pwn import *
from Crypto.Util.number import *
from tqdm import trange
def check(n):
    while True:
        a = getPrime(n)
        if isPrime(a+2):
            # print(a, b)
            break
    n = a - 1
    return n
li = []
for i in trange(64, 1000):
    li.append(check(i))
print('table is reday')

nc = remote('65.109.192.143', 37771)
for i in range(19):
    nc.recvuntil(b'Please submit an ')
    tmp = nc.recv().strip()
    kbit = eval(tmp[:tmp.index(b'-')])
    nc.sendline(f'{li[kbit-64]}'.encode())
    print(f'roll {i+1} is {kbit}')
nc.interactive()
```

等生成twin prime时间还是太长了，先多开几个程序一起跑生成64-1000以内整数后汇总

```python
from pwn import *
li = open(r'twin prime.txt').read()
li = li.strip().split('\n')
nc = remote('65.109.192.143', 37771)
for i in range(19):
    nc.recvuntil(b'Please submit an ')
    tmp = nc.recv().strip()
    kbit = eval(tmp[:tmp.index(b'-')])
    nc.sendline(f'{li[kbit-64]}'.encode())
    print(f'roll {i+1} is {kbit}')
nc.interactive()
```

## Goliver

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from flag import flag

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc(): 
	return sys.stdin.buffer.readline()

def ADD(A, B):
	s = (B[1] - A[1]) * inverse(B[0] - A[0], p) % p
	x = (s ** 2 - A[0] - B[0]) % p
	y = (s * (A[0] - x) - A[1]) % p
	return (x, y)

def DOUBLE(A):
	s = ((3 * A[0] **2 + a) * inverse(2 * A[1], p)) % p
	x = (s ** 2 - 2 * A[0]) % p
	y = (s * (A[0] - x) - A[1]) % p
	return (x, y)

def MUL(A, d):
	_B = bin(d)[2:]
	_Q = A
	for i in range(1, len(_B)):
		_Q = DOUBLE(_Q);
		if _B[i] == '1':
			_Q = ADD(_Q, A);
	return _Q

def GENKEY():
	skey = getRandomRange(1, p)
	assert (G[1] ** 2 - G[0] ** 3 - a * G[0] - b) % p == 0
	pubkey = MUL(G, skey)
	if pubkey[1] % 2 == 0:
		pkey = "02" + hex(pubkey[0])[2:].zfill(64)
	else:
		pkey = "03" + hex(pubkey[0])[2:].zfill(64)
	return (pkey, skey)

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, "Welcome to the Goliver World! You can play with ECC points on BTC ", border)
	pr(border, "curve. Your mission is to find the secret key and sweep wallets!  ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global p, a, b, G
	p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
	a, b = 0, 7
	n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
	x = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
	y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
	G = (x, y)
	pkey, skey = GENKEY()
	level, STEP, _b = 0, 10, False
	while True:
		pr("| Options: \n|\t[E]ncrypt point \n|\t[G]et the flag \n|\t[P]ublic key \n|\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'e':
			pr(border, f"Please provide your desired point `H` on the Secp256k1 curve:")
			inp = sc().decode()
			try:
				_x, _y = [int(_) for _ in inp.split(',')]
				if (_x**3 + a * _x + b - _y**2) % p < 0x0f:
					_b = True
			except:
				die(border, f"The input point you provided is not valid!")
			if _b:
				_Q = MUL((_x, _y), skey)
				print(border, f"skey * H = {_Q}")
				if level == STEP:
					die(border, f'You have only {STEP} rounds to compute.')
				else:
					level += 1
			else:
				die(border, f'The input point is not on the curve! Bye!!')
		elif ans == 'g':
			pr(border, 'Please send the private key: ')
			_skey = sc().decode()
			try:
				_skey = int(_skey)
			except:
				die(border, 'The private key is incorrect! Quitting...')
			if _skey == skey:
				die(border, f'Congrats, you got the flag: {flag}')
			else:
				die(border, f'The private key is incorrect! Quitting...')
		elif ans == 'p':
			pr(border, f'pubkey = {pkey}')
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()
```

椭圆曲线计算点乘时没有调用`b`变量，`b`只是判断是否落在点上

```python
try:
	_x, _y = [int(_) for _ in inp.split(',')]
	if (_x**3 + a * _x + b - _y**2) % p < 0x0f:
		_b = True
```

输入并不是一定要是曲线上点，只要模`p`时结果小于`15`就行，可以看作$y^2=x^3$，映射到整数域上
$$
(x,y)\to(\frac{x}{y})
$$
最简单就是传入`(1,1)`组合，求逆直接就是密钥

```python
from Crypto.Util.number import *
from random import *
from pwn import *

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
F = GF(p)

sh = remote("65.109.204.171", 17371)
sh.sendline(b"e")
sh.recvuntil(b"Please provide your desired point `H` on the Secp256k1 curve:")

sh.sendline((str(1)+","+str(1)).encode())
sh.recvuntil(b"skey * H = ")
x1,y1 = eval(sh.recvline().strip().decode())


sk = int(F(x1)/F(y1))
sh.sendline(b"g")
sh.recvuntil(b'Please send the private key: ')
sh.sendline(str(sk).encode())
sh.recvuntil(b"you got the flag: ")
print(sh.recvline())
```

## Heidi

```python
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def genkey(nbit):
	k = nbit >> 6
	p, l = getPrime(nbit), k << 1
	while True:
		M = matrix(GF(p), [[randint(0, p) for _ in range(l)] for _ in range(l)])
		if M.is_invertible():
			return p, M

def encrypt(m, key):
	p, M = key
	k = M.nrows() // 2
	u, v = [vector(randint(0, p) for _ in range(k)) for _ in '01']
	u[k - 1], U = m - sum(u[:-1]) % p, []
	for i in range(k):
		U += [(v[i] * u[i]) % p, v[i]]
	return M.inverse() * vector(U)

nbit = 512
key = genkey(nbit)
               
l = len(flag)
m1, m2 = bytes_to_long(flag[:l//2]), bytes_to_long(flag[l//2:])

c1 = encrypt(m1, key)
c2 = encrypt(m2, key)

print(f'p  = {key[0]}')
print(f'M  = {key[1]}')
print(f'c1 = {c1}')
print(f'c2 = {c2}')
```

M是16*16矩阵，U是根据v和u生成的，同时U左八数为运算结果，右八数为原数组，可以恢复出u。恢复出u之后只要求和就行。
$$
C=M^{-1}*U\Rightarrow M*C=U
$$

```python
f = open(r'D:\ctf\Heidi_I\output.txt').read()
exec(f)
M = matrix(GF(p), M)
c1, m2 = matrix(GF(p), c1), matrix(GF(p), c2)
U1 = M*c1.transpose()
u1 = [i/j for i,j in zip(U1[::2], U1[1::2])]
U2 = M*c2.transpose()
u2 = [i/j for i,j in zip(U2[::2], U2[1::2])]
long_to_bytes(int(sum(u1)))+long_to_bytes(int(sum(u2)))
```

# Forensics

## Cosmopolitan

一个pdf文件，三张图片，里面啥都没有了，pdftotext没效果，binwalk上去也没东西，然后继续去解密码，赛后才知道pdf可以改成ico打开，直接读取到flag；虽然说`00 00 01 00 01 00`是ico文件头，但在一些游戏的ico文件中，我看到头是`00 00 01 00 04 00`
