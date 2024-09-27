---
date: "2024-06-10"
title: 2024CryptoCTF
---
## Easy

### *behead_me

```bash
#!/bin/bash

source secrets.sh

FLAGS="all_flags.txt"
rm -f "all_flags.enc"

while read flag; do
	magick -background white -fill blue -pointsize 72 -size "$X"x"$Y" -gravity North caption:"$flag" flag.ppm
	tail -n +4 flag.ppm > tail
	openssl enc -aes-256-ecb -pbkdf2 -nosalt -pass pass:"$KEY" -in tail >> "all_flags.enc"
done < "$FLAGS"
```

先是`source secrets.sh`，在里面读取了`X,Y,flag,KEY`四个值，在读取`all_flags.txt`时，每读到一个带`flag`字符行，就创建一张白色背景蓝色字体，大小为(X,Y)的图片，格式为ppm文件，这类文件可用`GIMP`打开。

生成一张图片试试效果

```
magick -background white -fill blue -pointsize 72 -size "400"x"100" -gravity North caption:"flag{fake}"
flag.ppm
```

生成的`flag.ppm`用`01`打开，开头有

```
P6
400 100
65535
```

继续执行`tail -n +4 flag.ppm > tail`，发现`tail`文件头部信息没有了，只有下面的数据，那么`tail`这句就是起到隐藏宽高等信息作用，之后便是用`openssl`对每张图片进行`aes`加密并将数据追加到`all_flags.enc`。对前面生成的`flag.ppm`加密后发现可用直接用`GIMP`读取(注意后缀得是data)，读取时图像类型选`RGB`，宽度是原先的2倍，即`400`，选`RGB透明`、`RGB565大端`等时，宽度是原先的3倍，即`1200`

```
openssl enc -aes-256-ecb -pbkdf2 -nosalt -pass pass:"123456" -in tail > "al
l.data"
```

这时候注意下三个文件的字节数

```
wc -c flag.ppm	# 240017 flag.ppm
wc -c all.data	# 240016 all.data
wc -c tail	# 240000 tail
wc -c all_flags.enc	# 100691360 all_flags.enc
```

会发现$240000=2*400*100$，但因为`all.data`进行了填充，所以并不能准确判断宽高，只能通过爆破尝试，首先多张图片组合而成，先对`100691360`进行分解，因子有`2,5,7,11,743`几种情况，最后发现当取$2*5*11=110$张图片时，对`all_flags.enc`重命名成`all_flags.data`用`GIMP`打开，选择`RGB565`模式，宽高取`4869*10340`即可看到图像。

### *Mashy

```python
#!/usr/bin/env python3

import sys
from hashlib import md5
from binascii import *
from secret import salt, flag

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.buffer.readline()

def xor(s1, s2):
	return bytes([s1[_] ^ s2[_] for _ in range(len(s1))])

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".: Hi all, she did Mashy, you should do it too! Are you ready? :. ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

	REC = []
	cnt, STEP = 0, 7
	sh = md5(salt).digest()
	
	while True:
		pr(border, f'Please send your first input:  ')
		d1 = sc().strip()
		pr(border, f'Please send your second input: ')
		d2 = sc().strip()
		try:
			d1 = hexlify(unhexlify(d1))
			d2 = hexlify(unhexlify(d2))
			h1 = md5(unhexlify(d1)).digest()
			h2 = md5(unhexlify(d2)).digest()
		except:
			die(border, 'Your inputs are not valid! Bye!!!')
		if d1 != d2 and d1 not in REC and d2 not in REC:
			if md5(xor(d1, d2)).hexdigest() != 'ae09d7510659ca40eda3e45ca70e9606':
				if hexlify(xor(xor(h1, h2), sh)) == b'a483b30944cbf762d4a3afc154aad825':
					REC += [d1, d2]
					if cnt == STEP:
						die(border, f'Congrats! the flag: {flag}')
					pr(border, 'Good job, try next level :P')
					cnt += 1
				else:
					die(border, 'Your input is not correct! Bye!')
			else:
				die(border, 'No this one! Sorry!!')
		else:
			die(border, 'Kidding me!? Bye!!')

if __name__ == '__main__':
	main()
```

需要构造两个字符满足如下等式

`md5(d1^d2)!=ae09d7510659ca40eda3e45ca70e9606`且

`md5(d1)^md5(d2)^md5(salt)==a483b30944cbf762d4a3afc154aad825`

赛时没有意识到`a483b30944cbf762d4a3afc154aad825`就是`md5(salt)`，所以一直想不通如何构造，如果想到这点，那么这题就是找到八组`md5`相同的`d1,d2`，直接网上找，就找到两组，然后发现[`fastcoll`](www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip)工具专门用于`md5`碰撞，那么便用这个工具试试。在`fastcoll_v1.0.0.5.exe`同级目录下新建个`1.txt`，直接进入`cmd`

```bash
fastcoll_v1.0.0.5.exe -p 1.txt -o 11.txt 12.txt
```

那么`11.txt`和`12.txt`便是`md5`相同的不同文件，用`python`输出十六进制方便复制

```python
from binascii import hexlify
a = open('11.txt', 'rb').read()
b = open('12.txt', 'rb').read()
print(hexlify(a), hexlify(b), sep=', ')
```

之后就是交互，只要八组数据就行

```python
from pwn import *
r = remote('00.cr.yp.toc.tf', 13771)
ds = [(b"0e306561559aa787d00bc6f70bbdfe3404cf03659e704f8534c00ffb659c4c8740cc942feb2da115a3f4155cbb8607497386656d7d1f34a42059d78f5a8dd1ef", b"0e306561559aa787d00bc6f70bbdfe3404cf03659e744f8534c00ffb659c4c8740cc942feb2da115a3f415dcbb8607497386656d7d1f34a42059d78f5a8dd1ef"),
      (b"4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2", b"4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2"),
      (b'FCD56559D228B389629C1A82609905D5134A992BC53949A133CE3ED2B91ABCFBD29DCE11BE6FDB7E8F1C49792FBC2E0FAD27B2DBA79DF61DCCA3BE85F353C5CE3F3AE087A3EA74CBE93E248C645238FD031507267F57F02C20395BC5D12951AF31E73509DA93B1483A72C1A99DC0F17CF2804CA975C013D7CBD83BFC27CF00B8', b'FCD56559D228B389629C1A82609905D5134A99ABC53949A133CE3ED2B91ABCFBD29DCE11BE6FDB7E8F1C49792F3C2F0FAD27B2DBA79DF61DCCA3BE05F353C5CE3F3AE087A3EA74CBE93E248C645238FD031507A67F57F02C20395BC5D12951AF31E73509DA93B1483A72C1A99D40F17CF2804CA975C013D7CBD83B7C27CF00B8'),
      (b'A390DB1F36DB04C082AA9AA12232415D12AD524956268122284E7A05CD8C0F50BCDBC400CC0CF446074651BA0DCE3E115593DBD57B6E43A434E10167CBC84FC8A72188BDED64B63C4DF7E2B14E1C29586F57D64D07EA8E5F7E89CF4F5B5D254165F4B48E066882F69D91EFD884CAF102634329F4DBBD6344DE5A78B46163BA48', b'A390DB1F36DB04C082AA9AA12232415D12AD52C956268122284E7A05CD8C0F50BCDBC400CC0CF446074651BA0D4E3F115593DBD57B6E43A434E101E7CBC84FC8A72188BDED64B63C4DF7E2B14E1C29586F57D6CD07EA8E5F7E89CF4F5B5D254165F4B48E066882F69D91EFD8844AF102634329F4DBBD6344DE5A78346163BA48'),
      (b'3A8D1793849EA9877846EAF5ED2D5A34F94C73A6C17C96F2088E43E504ACA66C931106DF4EAF2FE947623CD4D4C5BE2D7A57A6A756EEA69886FF8DD51437E720CF4CD1BB4659F19795299C1A6762D3E6BF15BDA5BD6740EE1449A22749EB0C6EA517B34D5D0D57C5C685095299E8B6DDF99843D396BE730C5417FAE605A06069', b'3A8D1793849EA9877846EAF5ED2D5A34F94C7326C17C96F2088E43E504ACA66C931106DF4EAF2FE947623CD4D445BF2D7A57A6A756EEA69886FF8D551437E720CF4CD1BB4659F19795299C1A6762D3E6BF15BD25BD6740EE1449A22749EB0C6EA517B34D5D0D57C5C68509529968B6DDF99843D396BE730C5417FA6605A06069'),
      (b'7f50f48f6eadf633594d84fd7be0ef127f469b2a0d0520a7307277796cb02e109f1df2d2cc02546feb05611ccc03689e1a3b9677161fbc88feed4b5849154e29c2dc329df050c6ac5ddd60f909ff4246b809c523f93d601dd17b13cdd06859aeb1691edf6acbae649d48b1cfe0be6ea8dcde6ff9ffef82e6ecd13c6619558491', b'7f50f48f6eadf633594d84fd7be0ef127f469baa0d0520a7307277796cb02e109f1df2d2cc02546feb05611ccc83689e1a3b9677161fbc88feed4bd849154e29c2dc329df050c6ac5ddd60f909ff4246b809c5a3f93d601dd17b13cdd06859aeb1691edf6acbae649d48b1cfe03e6ea8dcde6ff9ffef82e6ecd13ce619558491'),
      (b'fa579e410262d67c3faaab87528ac438fa0be3976665164a40b640d94e061ee7ffe3c4d34eac561d6fe4631bd8b1506ea50fca0bf4af7e0392e4e8894c0902648524f9e8708f3b4ea36d55fb1e1ae05bb134ab48e3e91a9f84e7cb4f5f5c2541f47dad8df4a58bff2abaebf863e8602f03612757ea937f095c2966721eef3c10', b'fa579e410262d67c3faaab87528ac438fa0be3176665164a40b640d94e061ee7ffe3c4d34eac561d6fe4631bd831516ea50fca0bf4af7e0392e4e8094c0902648524f9e8708f3b4ea36d55fb1e1ae05bb134abc8e3e91a9f84e7cb4f5f5c2541f47dad8df4a58bff2abaebf86368602f03612757ea937f095c2966f21eef3c10'),
      (b'db3607019eaf0998e29f9ac1ae947d70f1d540ed0b36614e11d63ec633082c2f5afaa1ec4c4c08038f40749230142a26b627afd59a917d61b2c89496c3f1b4213705b5f9b38b7c42fbc649480d7f45c5403017b6c9c87afc101db5c6cd0d8dde097ffb2dc410c767467505b29d50ba7ec6649e2d75b773325257f070e3753a9b', b'db3607019eaf0998e29f9ac1ae947d70f1d5406d0b36614e11d63ec633082c2f5afaa1ec4c4c08038f40749230942a26b627afd59a917d61b2c89416c3f1b4213705b5f9b38b7c42fbc649480d7f45c540301736c9c87afc101db5c6cd0d8dde097ffb2dc410c767467505b29dd0b97ec6649e2d75b773325257f0f0e3753a9b')
      ]
for d in ds:
    r.recvuntil(b"first input:")
    r.sendline(d[0])
    r.recvuntil(b"second input:")
    r.sendline(d[1])
r.interactive()
```



### alibos

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from gmpy2 import *
from secret import d, flag

get_context().precision = 1337

def pad(m, d):
	if len(str(m)) < d:
		m = str(m) + '1' * (d - len(str(m)))
	return int(m)

def genkey(d):
	skey = getRandomRange(10 ** (d - 1), 10 ** d)
	pkey = int(10**d * (sqrt(skey) - floor(sqrt(skey))))
	return pkey, skey

def encrypt(m, pkey):
	m = pad(m, len(str(pkey)))
	d = len(str(pkey))
	c = (pkey + d ** 2 * m) % (10 ** d)
	return c

pkey, skey = genkey(d)

m = bytes_to_long(flag)
c = encrypt(m, pkey)

print(f'pkey = {pkey}')
print(f'enc  = {c}')
```

$$
c\equiv pkey+d^2*m\mod 10^d\\
m\equiv (d^2)^{-1}(c-pkey)\mod 10^d
$$

注意拿到的`m`是经过`pad`加密的，那么只要将末尾的`1`全部拿掉

```python
from Crypto.Util.number import *
pkey = 8582435512564229286688465405009040056856016872134514945016805951785759509953023638490767572236748566493023965794194297026085882082781147026501124183913218900918532638964014591302221504335115379744625749001902791287122243760312557423006862735120339132655680911213722073949690947638446354528576541717311700749946777
enc  = 6314597738211377086770535291073179315279171595861180001679392971498929017818237394074266448467963648845725270238638741470530326527225591470945568628357663345362977083408459035746665948779559824189070193446347235731566688204757001867451307179564783577100125355658166518394135392082890798973020986161756145194380336
d = 313
m = (enc-pkey)*inverse(d**2, 10**d)%10**d
print(m)
print(int(str(m).rstrip('1'), 10))
```

## Medium

### alilbols

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from gmpy2 import *
from secret import d, flag

def genkey(d):
	while True:
		f = getRandomRange(1, int(sqrt(2) * 10 ** d))
		g = getRandomRange(10 ** d, int(sqrt(2) * 10 ** d))
		if gcd(f, 10 * g) == 1:
			q = 4 * 100 ** d
			h = inverse(f, q) * g % q
			if gcd(h, 10 * d) == 1:
				break
	pkey, skey = (d, h), (f, g)
	return pkey, skey

def encrypt(m, pkey):
	d, h = pkey
	q = 4 * 100 ** d
	assert m < 10 ** d
	r = getRandomRange(1, 10 ** d // 2)
	c = (r * h + m + r) % q
	return c

pkey, _ = genkey(d)
m = bytes_to_long(flag)
c = encrypt(m, pkey)

print(f'h = {pkey[1]}')
print(f'c = {c}')
```

$$
q=4*100^d\\
h\equiv f^{-1}g\mod q\\
c\equiv rh+m+r\equiv r(h+1)+m\mod q\\
f*c\equiv r*g+f*m+f*r\mod q
$$

`f,g`相对`q`来说是小量，那么这是`NTRU`问题，用`LLL`恢复出`f,g`
$$
t=f*c\equiv r*(f+g)+f*m\mod q\\
t\equiv f*m \mod (f+g)\\
m\equiv f^{-1}*t\mod (f+g)
$$
注意最后的$f^{-1}$是在$\mod (f+g)$下，与之前在`mod q`下的`f`不是同一个数，没办法直接消去

```python
M = matrix(ZZ, [[1, h], [0, q]])
f, g = M.LLL()[0]
q = 40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
f = 113064947692702103799231199468072510903839498374716047303085853453113283728818247305758215677954588763931471946182908063714777335122912930256571619331664053621631174370186578849231886568333948343534395353919774419633731806963043911274007420241089284010144207714339617510789422811656735331222466776153901647025851637829858405953050072469297992493334984730777005154182274995099150706806282346277695670937656012866815920565404878131472860889178457719003956941536200135614026090372738773201706091708638664496577612244017928430272852213629449803865503473673985014191137
g = 121225735948962805927435238039810819215887992413542216149877302158471567001614227054453188896976336350561801244215667264722788859622407059935854582497557238535977706646667824468703286568029648346697105178986470102548390104380856939377786046149771635771656620472465696255524883500461088148118520891769358583188198505080807288139862744022281798728618135336019815478870827242841306653937757979436969147775800185012065008310407495836925318623318860872984004964969550906585353801421678977298537476134466756779438293960694910065864999873778057675968654079621038359759233
print(f<2*10**d, g>10**d, g<2*10**d, h==(inverse(f, q)*g%q))
m = f*c % q % (f+g)
m = m * inverse(f, f+g) % (f+g)
print(long_to_bytes(m))
```

### Joe-19

```python
#!/usr/bin/env sage

from GPT import GPT6 # deep fake 
from Crypto.Util.number import *
from flag import flag

P = [GPT6('A 512-bit prime appears in consecutive digits of e') for _ in range(4)]
n, m = prod(P), bytes_to_long(flag)
c = pow(m, 0x10001, n)
print(f'n = {n}')
print(f'c = {c}')
```

赛时对`A 512-bit prime appears in consecutive digits of e`确实不理解，但通过`factordb`查表直接得到因子；实际上这句话意思是在自然对数`e`中，截取出一个`512`位的质数，

```python
import mpmath
mpmath.mp.dps = 20000
n = 8098851734937207931222242323719278262039311278408396153102939840336549151541408692581651429325092535316359074019383926520363453725271849258924996783681725111665666420297112252565291898169877088446887149672943461236879128453847442584868198963005276340812322871768679441501282681171263391133217373094824601748838255306528243603493400515452224778867670063040337191204276832576625227337670689681430055765023322478267339944312535862682499007423158988134472889946113994555274385595499503495488202251032898470224056637967019786473820952632846823442509236976892995505554046850101313269847925347047514591030406052185186963433

e = str(mpmath.e).replace('.', '')
length = 154

for i in range(len(e) - length + 1):
    p = int(e[i:i + length])
    if (n % p == 0):
        print(f"Found a 512-bit prime: {p}")
else:
    print("No 512-bit prime found in the specified range of digits.")
```

通过`mpmath`调整`dps`后可以更多的显示`e`的完整数字，`512`位对应十进制大概是`154`，那么需要求出的`p`的长度就是`154`，每次取`154`个连续字符作为整数，判断是不是`n`的因子，最后可以得到一个因子

```python
from Crypto.Util.number import *
n = 8098851734937207931222242323719278262039311278408396153102939840336549151541408692581651429325092535316359074019383926520363453725271849258924996783681725111665666420297112252565291898169877088446887149672943461236879128453847442584868198963005276340812322871768679441501282681171263391133217373094824601748838255306528243603493400515452224778867670063040337191204276832576625227337670689681430055765023322478267339944312535862682499007423158988134472889946113994555274385595499503495488202251032898470224056637967019786473820952632846823442509236976892995505554046850101313269847925347047514591030406052185186963433
p = 7728751393377105569802455757436190501772466214587592374418657530064998056688376964229825501195065837843125232135309371235243969149662310110328243570065781
c = 7109666883988892105091816608945789114105575520302872143453259352879355990908149124303310269223886289484842913063773914475282456079383409262649058768777227206800315566373109284537693635270488429501591721126853086090237488579840160957328710017268493911400151764046320861154478494943928510792105098343926542515526432005970840321142196894715037239909959538873866099850417570975505565638622448664580282210383639403173773002795595142150433695880167315674091756597784809792396452578104130341085213443116999368555639128246707794076354522200892568943534878523445909591352323861659891882091917178199085781803940677425823784662
d = inverse(65537, p-1)
print(long_to_bytes(pow(c, d, p)))
```



### *honey

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from math import sqrt
from flag import flag

def gen_params(nbit):
	p, Q, R, S = getPrime(nbit), [], [], []
	d = int(sqrt(nbit << 1))
	for _ in range(d):
		Q.append(getRandomRange(1, p - 1))
		R.append(getRandomRange(0, p - 1))
		S.append(getRandomRange(0, p - 1))
	return p, Q, R, S

def encrypt(m, params):
	p, Q, R, S = params
	assert m < p
	d = int(sqrt(p.bit_length() << 1))
	C = []
	for _ in range(d):
		r, s = [getRandomNBitInteger(d) for _ in '01']
		c = Q[_] * m + r * R[_] + s * S[_]
		C.append(c % p)
	return C


nbit = 512
params = gen_params(512)
m = bytes_to_long(flag)
C = encrypt(m, params)
f = open('params_enc.txt', 'w')
f.write(f'p = {params[0]}\n')
f.write(f'Q = {params[1]}\n')
f.write(f'R = {params[2]}\n')
f.write(f'S = {params[3]}\n')
f.write(f'C = {C}')
f.close()
```

`get_params`中`d`是32，那么`Q,R,S`长度都是32，`encrypt`中`d`也是32
$$
c_0\equiv m*Q_0+r_0*R_0+s_0*S_0\\
c_1\equiv m*Q_1+r_1*R_1+s_1*S_0\\
\cdots\\
Q_1c_0\equiv mQ_0Q_1+r_0R_0Q_1+s_0S_0Q_1\\Q_0c_1\equiv mQ_1Q_0+r_1R_1Q_0+s_1S_1Q_0\\
r_0R_0Q_1+s_0S_0Q_1-r_1R_1Q_0-s_1S_1Q_0+Q_0c_1-Q_1c_0+kp=0\\
\left[\begin{matrix}{}0&r_0&s_0&-r_1&-s_1&-k&1\end{matrix}\right]*\left[\begin{matrix}{}R_0Q_1&S_0Q_1&R_1Q_0&S_1Q_0&\quad p&Q_0c_1-Q_1c_0\\1&0&0&0&\quad0&0\\0&1&0&0&\quad0&0\\0&0&1&0&\quad0&0\\0&0&0&1&\quad0&0\\0&0&0&0&\quad1&0\\0&0&0&0&\quad0&1\end{matrix}\right]
$$

```python
#!/usr/bin/env python3

from sage.all import identity_matrix, Matrix


with open('params_enc.txt') as f:
    exec(f.read())

B = 2 ** 512

M = Matrix([
        [
        R[0] * Q[1] % p,
        S[0] * Q[1] % p,
        R[1] * Q[0] % p,
        S[1] * Q[0] % p,
        p,
        (Q[0] * C[1] - Q[1] * C[0]) % p
    ]
]).stack(identity_matrix(6))

M[-1, -1] = B

L = M.T.LLL()
row = L[-1]
assert row[0] == 0 and row[-1] == B

r0, s0 = row[1:3]
m = (C[0] - r0 * R[0] - s0 * S[0]) * pow(Q[0], -1, p) % p
print(bytes.fromhex(hex(m)[2:]).decode())
```



### RM2

```python
#!/usr/bin/env python3

import sys
from Crypto.Util.number import *
from string import *
from random import *
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

def randstr(l):
	return ''.join([printable[randint(0, 90)] for _ in range(l)])

def encrypt(msg, p, q):
	e = 65537
	m1, m2 = msg[:len(msg) >> 1], msg[len(msg) >> 1:]
	m1, m2 = bytes_to_long(m1), bytes_to_long(m2)
	c1, c2 = pow(m1, e, (p - 1) * (q - 1)), pow(m2, e, (2*p + 1) * (2*q + 1))
	return (c1, c2)

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".: Welcome to RM2 task! Your mission is break our cryptosystem :. ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	nbit, _b = 1024, False
	pr(border, f"Please provide your desired {nbit}-bit prime numbers p, q:")
	inp = sc().decode()
	try:
		p, q = [int(_) for _ in inp.split(',')]
		if p.bit_length() == q.bit_length() == nbit and isPrime(p) and isPrime(q) and p != q:
			_b = True
	except:
		die(border, f"The input you provided is is not valid!")
	if _b:
		e, n =  65537, p * q
		s = randstr(nbit >> 4).encode()
		m = bytes_to_long(s)
		assert m < n >> 2
		c1, c2 = encrypt(s, p, q)
		pr(border, f'c1 = {c1}')
		pr(border, f'c2 = {c2}')
		pr(border, f'Now, send us the secret string to get the flag: ')
		_m = sc().strip()
		if _m == s:
			die(border, f'Congrats, you got the flag: {flag}')
		else:
			die(border, f'The secret string is not correct! Bye!!')
	else:
		die(border, f"Your input does not meet the requirements!!!")

if __name__ == '__main__':
	main()
```

可以发现`p,q`是我们自己传入的数据，同时加密用的不是`p*q`，而是`(p-1)*(q-1)`和`(2*p+1)*(2*q+1)`，构造`p-1`光滑和`2q+1`光滑，分别用一个模数求解

```python
from Crypto.Util.number import *
from random import choice
from pwn import *

def p_minus_one(bits):
    while True:
        n = 2
        while n.bit_length() < bits:
            n *= choice(sieve_base)
        if isPrime(n + 1):
            return n + 1

def p_plus_one(bits):
    while True:
        n = 2
        while n.bit_length() < bits:
            n *= choice(sieve_base)
        n = n-1
        if isPrime(n//2):
            return n//2
while True:
    p = p_minus_one(1024)
    if p.bit_length() == 1024:
        print(p)
        print(p.bit_length())
        break

while True:
    q = p_plus_one(1024)
    if q.bit_length() == 1024:
        print(q)
        print(q.bit_length())
        break

p, phip = 176620292400683861608905276314000953341545911132390641856161270066070310094574346950050500545254022678976109002145505156971629821463466628739552159346010873468956041108855657073267083603529603410463002356608043401778510237268428228518269057982203633440480326104620254741905629697429019006031404025025140895759, 87465439332683559535714272346712901640788167333918158097876056435329511959556428907739679846596005394177082309352032163087006001800144068856680694016033768141684268992517141311399484906444443690627706905349862220987068292756718510514705700332875886301199603133766797277714167361113670696388526080000000000000
q, phiq = 125252426228609337339815458415274580435049901593326124996215548029924951849155396950022414267768238267598182097716991713113543518658849067982511610254114064962720384213122832074059104122373116415869397082955705893721798127582397652415786695330120461678539543068275795763552254969738083419754475973124685205661, 140675775467823414877709765167893024545799918390446278372180411258908033060081122664079645586696185111567272435178350167971250209439439246432845288514219865235765957517631957817444760658545178288113255378476046767110948913166511704822479193525492083464100786097262846988972496436690407351209938539210525499392

nc = remote('01.cr.yp.toc.tf', 13371)
nc.sendline(f'{p},{q}'.encode())
nc.recvuntil(b'c1 = ')
c1 = int(nc.recvline()[:-1])
nc.recvuntil(b'c2 = ')
c2 = int(nc.recvline()[:-1])

e = 65537
n1 = (p-1)*(q-1)
n2 = (2*p+1)*(2*q+1)
# c = pow(2, e, 2*q+1)
# print(pow(c, inverse(e, phiq), 2*q+1))
m1 = pow(c1, inverse(e, phip), p-1)
m2 = pow(c2, inverse(e, phiq), 2*q+1)
nc.sendline(long_to_bytes(m1)+long_to_bytes(m2))
nc.interactive()

```

`phi`用`sagemath`算即可，光滑下算得很快，`phip`是$\varphi(p-1)$，`phiq`是$\varphi(2*q+1)$

赛后想清楚实际上`q`并不需要用光滑，如果`2q+1`也是质数就行，那么`q`也可以用这样的式子生成，虽然都是基于随机数，但感觉概率会比光滑高

```python
from Crypto.Util.number import *
from random import choice
import time

a = time.time()
while True:
    q = getPrime(1024)
    if isPrime(2*q+1):
        print(q)
        print(time.time() - a)
        break

# 147311399066756055931938977631294702169592241130169884224379996505013905814122303722836956630875735691195149340718209448605719692947091202159492306913570823944573430306826180052034824000472541723130528803814472206528298094034745812850691358205670794221826538460097744876689773138118025298846130550912815087633
# 123.99886226654053
```

同样会光滑思想去跑了一遍，时间是`232.0996527671814`

### melek

```python
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def encrypt(msg, nbit):
	m, p = bytes_to_long(msg), getPrime(nbit)
	assert m < p
	e, t = randint(1, p - 1), randint(1, nbit - 1)
	C = [randint(0, p - 1) for _ in range(t - 1)] + [pow(m, e, p)]
	R.<x> = GF(p)[]
	f = R(0)
	for i in range(t): f += x**(t - i - 1) * C[i]
	P = [list(range(nbit))]
	shuffle(P)
	P = P[:t]
	PT = [(a, f(a)) for a in [randint(1, p - 1) for _ in range(t)]]
	return e, p, PT

nbit = 512
enc = encrypt(flag, nbit)
print(f'enc = {enc}')
```

$$
f(x)=c_0x^{t-1}+c_1x^{t-2}+\cdots+c_ix^{t-i-1}+\cdots\\
\left[\begin{matrix}c_0&c_1&\cdots&c_{t-1}\end{matrix}\right]*\left[\begin{matrix}
a_0^{t-1}&a_1^{t-1}&\cdots&a_{t-1}^{t-1}\\
a_0^{t-2}&a_1^{t-2}&\cdots&a_{t-1}^{t-2}\\
&\cdots\\
a_0^{0}&a_1^{0}&\cdots&a_{t-1}^{0}\end{matrix}\right]=\left[\begin{matrix}f(a_0)&f(a_1)&\cdots&f(a_{t-1})\end{matrix}\right]
$$

```python
exec(open('D:/ctf/melek/output.txt').read())
e, p, pt = enc
t = len(pt)
a, c = [0]*t, [0]*t
for i in range(t):
	a[i], c[i] = pt[i]

fa = [[0]*t for _ in range(t)]
for i in range(t):
    for j in range(t):
        fa[j][i] = pow(a[i], t-j-1, p)

mid = matrix(GF(p), fa)
right = matrix(GF(p), c)
res = mid.solve_left(right)
```

拿出`res`最后一行最后一个数字为密文`c`，对其进行求解

```python
from gmpy2 import *
from Crypto.Util.number import *
import random
import math

e = 3316473234742974510609176519968107496789324827839883341690084725836178910956015867823194881383215644380418162164089588828798132617649547462723383625707014
p = 9486915681801496583557174944405629563403346572353787092582704754226121096049954529719556720667960706741084895049852989479773192757968901195529919070579679
c2 = 7578451683223886721897751965012512970186814199061886859082385728532294810974986601048390882041773215459258245487361965408708218417206386123135513829067466
# GCD(e, p-1)==2
d = inverse(e//2, p-1)
c2 = (pow(c2, d, p))
e = 2

def onemod(e, q):
    p = random.randint(1, q-1)
    while(powmod(p, (q-1)//e, q) == 1):  # (r,s)=1
        p = random.randint(1, q)
    return p

def AMM_rth(o, r, q):  # r|(q-1
    assert((q-1) % r == 0)
    p = onemod(r, q)

    t = 0
    s = q-1
    while(s % r == 0):
        s = s//r
        t += 1
    k = 1
    while((s*k+1) % r != 0):
        k += 1
    alp = (s*k+1)//r

    a = powmod(p, r**(t-1)*s, q)
    b = powmod(o, r*a-1, q)
    c = powmod(p, s, q)
    h = 1

    for i in range(1, t-1):
        d = powmod(int(b), r**(t-1-i), q)
        if d == 1:
            j = 0
        else:
            j = (-math.log(d, a)) % r
        b = (b*(c**(r*j))) % q
        h = (h*c**j) % q
        c = (c*r) % q
    result = (powmod(o, alp, q)*h)
    return result

def ALL_Solution(m, q, rt, cq, e):
    mp = []
    for pr in rt:
        r = (pr*m) % q
        # assert(pow(r, e, q) == cq)
        mp.append(r)
    return mp

def ALL_ROOT2(r, q):  # use function set() and .add() ensure that the generated elements are not repeated
    li = set()
    while(len(li) < r):
        p = powmod(random.randint(1, q-1), (q-1)//r, q)
        li.add(p)
    return li

mp = AMM_rth(c2, e, p)
rt1 = ALL_ROOT2(e, p)
amp = ALL_Solution(mp, p, rt1, c2, e)
for i in amp:
    tmp = long_to_bytes(i)
    if b'CCTF' in tmp:
        print(tmp)
```

### *vantuk

```python
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def u(a, x, y):
	assert a.is_integer() and x.is_rational() and y.is_rational()
	return x + Rational((a * x - y)/(x ** 2 + y ** 2))

def v(a, x, y):
	assert a.is_integer() and x.is_rational() and y.is_rational()
	return y - Rational((x + a * y)/(x ** 2 + y ** 2))

m1 = Integer(bytes_to_long(flag[:len(flag)//2]))
m2 = Integer(bytes_to_long(flag[len(flag)//2:]))
a = Integer(randint(1, 1 << 512))

print(f'A = {u(5, a, 4*a)}')
print(f'U = {u(a, m1, m2)}')
print(f'V = {v(a, m1, m2)}')
```

$$
A=a+\frac{5a-4a}{a^2+(4a)^2}=a+\frac{a}{17a^2}=\frac{17a^2+1}{17a}\\
U=m_l+\frac{a*m_l-m_h}{m_l^2+m_h^2}\\
V=m_h-\frac{m_l+a*m_h}{m_l^2+m_h^2}\\
$$

代码放在`sage10.3`中可执行，但不能放在`sage9.3`中，会报错抛出

```python
A = 6080057478320734754578252336954411086329731226445881868123716230995225973869803901199434606333357820515656618869146654158788168766842914410452961599054518002813068771365518772891986864276289860125347726759503163130747954047189098354503529975642910040243893426023284760560550058749486622149336255123273699589/10166660077500992696786674322778747305573988490459101951030888617339232488971703619809763229396514541455656973227690713112602531083990085142454453827397614
U = 3225614773582213369706292127090052479554140270383744354251548034114969532022146352828696162628127070196943244336606099417210627640399143341122777407316956319347428454301338989662689983156270502206905873768685192940264891098471650041034871787036353839986435/9195042623204647899565271327907071916397082689301388805795886223781949921278129819112624089473306486581983153439866384171645444456400131619437018878598534536108398238424609
V = 1971582892158351181843851788527088806814104010680626247728311504906886858748378948163011806974145871263749452213375101951129675358232283650086419295655854343862361076089682606804214329522917382524296561295274823374483828323983651110722084223144007926678084087/9195042623204647899565271327907071916397082689301388805795886223781949921278129819112624089473306486581983153439866384171645444456400131619437018878598534536108398238424609
a = var('a')
solve(A*17*a == (17*a*a+1), a)
a = 598038828088293688046274960163455723857293440615241291237111095137601911115982565871162542905677325967979821954570041947800148887293534420144379636905742
m1, m2 = var('m1 m2')
eq1 = U *(m1*m1+m2*m2) == m1 * (m1*m1+m2*m2) + a*m1-m2
eq2 = V *(m1*m1+m2*m2) == m2 * (m1*m1+m2*m2) - m1-a*m2
solve([eq1,eq2],m1,m2)
# [m1 == 350799328046836724707876331502758499088281144928479088116262376685681093677946249551, m2 == 214418026424679791626535920403147011577793961208832046224896849702981130286017264892462]
```

### *Bada

没有源码，只有交互网址，连接上是给两个等式算`x,y`

```python
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Hey! It's time to solve the equation of a function f: N x N -> Z.    ┃
┃ Function f has given certain conditions. In each step, solve the     ┃
┃ equation f(x, y) = z with the given value of z. We know f(a+1, b) =  ┃
┃ f(a, b) + a, and f(a, b+1) = f(a, b) - b, for every `a' and `b'.     ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┃ We know: f(1, 1) = 506703467839 and f(x, y) = 1236440673186
┃ Please send x, y separated by comma: 
```

$$
f(x,y)=z\qquad f(a+1,b)=f(a,b)+a\qquad f(a,b+1)=f(a,b)-b\\
f(1,1)=t\qquad f(2,1)=t+1\qquad f(3,1)=t+1+2\qquad f(x,1)=t+\sum_{i=1}^{x-1}i\\
f(1,1)=t\qquad f(1,2)=t-1\qquad f(1,3)=t-1-2\qquad f(1,y)=t-\sum_{i=1}^{y-1}i\\
f(x,x)=f(x,1)-\sum_{i=1}^{x-1}i=f(1,1)
$$

那么可以取`x=y+1`，$f(x,y)=f(y+1,y)=f(y,y)+y=f(1,1)+y$

```python
from pwn import *
nc = remote('00.cr.yp.toc.tf', 17113)
nc.recvuntil(b'We know: f(1, 1)')
for i in range(20):
    t = nc.recvline().split(b'and')
    x = eval(t[0].split(b'=')[-1])
    y = eval(t[1].split(b'=')[-1])
    print(x, y)
    y = y - x
    x = y+1
    nc.recvline()
    nc.sendline(f"{x},{y}".encode())
    print(nc.recvline())
    if i == 19:
        print(nc.recvline())
```

