---
date: "2024-07-02"
title: ECC
---

# ECC(椭圆曲线)

椭圆曲线密码学(Elliptic Curve Cryptography)是一种基于椭圆曲线数学的公开密钥加密算法。与传统的基于大质数因子分解困难性的加密方法不同，ECC依赖于解决椭圆曲线离散对数问题的困难性。它的优势主要在于相对于其它方法，它可以在使用较短密钥长度的同时保持相同的密码强度。目前椭圆曲线主要采用的有限域有以素数为模的整数域$GF(p)$和特征为$2$的伽罗华域$GF(2^m)$。

椭圆曲线定义式：$y^2+axy+by=x^3+cx^2+dx+e$

一般方程：$y^2+a_1xy+a_3y=x^3+a_2x^2+a_4x+a_6$

## 最常见方程

$$
y^2=x^3+ax+b
$$

判别式$\Delta=-16(4a^3+27b^2)\neq0$（关于判别式是$0$这点叫尖点，具体在下面`HXP CTF`例题内）

对于这样形式的方程，所出现的图像形状大致如下。

![335px-ECClines-3.svg](https://s2.loli.net/2023/12/09/IVXHslFzp3x51uK.png)

在椭圆曲线中存在无穷远点$O$(a point at infinity)，$O$通常看作$0$的标志，即零元。任何数与$0$相加都是本身，与$0$相乘都是$0$。$O$也是椭圆曲线的一部分，那么椭圆曲线的数学定义便是
$$
\{(x,y)\in\R^2\mid y^2=x^3+ax+b,\ 4a^3+27b^2\ne0\}\cup\{0\}
$$


椭圆曲线上的加法，与群中的加法类似，是一种重定义的运算，在几何意义上，可以将其看作是以两点做直线相加于椭圆曲线，这样得出的三点相加等于$O$，$O$是定义在椭圆曲线上的无穷远点，作用与加法中的$0$类似，任何点与$O$进行加法运算仍是这个点本身。

## 几何表示

取曲线上两点$P,Q$，$P+Q$便是以这两点做直线与曲线相交。$P+Q=-R$，式子也是$P+Q+R=0$。

![point-addition](https://s2.loli.net/2023/12/09/VlYtbHzosvGLZUC.png)

图一中$P+Q+R=0$，等效可以写作$P+Q=-R$，而$-R$相当于$R$点关于$x$轴对称。

图二等效为$Q+Q=-P$，这时候便是用一个点求直线，以$Q$点做切线与曲线相加，这个点便是$-P$。

图三$P,Q$关于$x$轴对称，两者相加必是无穷远点$O$。

![ECClines.svg](https://s2.loli.net/2023/12/09/SCkvHpt6lgR5ayd.png)

## 代数表示

代数运算相较几何更接近我们所需，毕竟程序都是用计算表示。

$P=(x_P,y_P),Q=(x_Q,y_Q)$
若$P$与$Q$不同，即$x_P\neq x_Q$，斜率$k=\frac{y_P-y_Q}{x_P-x_Q}$
若$P$与$Q$相同，即$x_P=x_Q$，斜率$k=\frac{3x_P^2+a}{2y_P}$
直线与曲线交点$R=(x_R,y_R)$，则:
$$
x_R=k^2-x_P-x_Q\\ y_R=y_P+k(x_R-x_P)=y_Q+k(x_R-x_Q)
$$
于是：$P+Q=(x_P,y_P)+(x_Q,y_Q)=-R=(x_R,-y_R)$

对点进行多次加法运算便是定义出来的乘法，$b_i$为$n$的各比特位值
$$
Q=nP=P+P+\cdots+P=\sum_{i=1}^{n-1}(b_i\cdot2^i)P,\quad b_i=\{0,1\}
$$
下面是扭曲爱德华曲线运算规则，其乘法思路与之相同，但更为简单，主要是对椭圆曲线本身的加法需要进行判断，比之爱德华曲线更加冗长。为方便起见，引用过来，看着熟悉熟悉。

细说如果$e=65537$，那么第一次便是将$Q$赋值为初始的$P$，在之后过程中，比特位不为$1$，对$Q$并不造成影响，$2P=P+P$，$4P=2P+2P$，$8P=4P+4P$，可以发现每个都是$P$的运算，且从幂次数来看都是$2^n$次方。直到读取到最后是$1$时，$Q=65536P+Q=65537P$，这不就完美实现了乘法所需要的功能。

```python
def add(P, Q):
    (x1, y1) = P
    (x2, y2) = Q
    x3 = (x1*y2 + y1*x2) * inverse(1 + d*x1*x2*y1*y2, p) % p
    y3 = (y1*y2 - a*x1*x2) * inverse(1 - d*x1*x2*y1*y2, p) % p
    return (x3, y3)

def mul(x, P):
    Q = (0, 1)
    while x > 0:
        if x % 2 == 1:
            Q = add(Q, P)
        P = add(P, P)
        x = x >> 1
    return Q
mul(e, G)
```

下面是$ECC$的加乘法运算实现，对于$ECC$运算，$Sagemath$里集成有工具，实际上并不需要人为定义。

```python
p = 
a = 
def ECCadd(Q, P, p, a):
    x1, y1 = Q
    x2, y2 = P
    if(x1 == x2):
        if((y1 + y2) % p == 0):
            return -1, -1
        elif(y1 != y2):
            print("Input Error")
            return -2, -2
        else:
            k = ((3 * x1 ** 2 + a) * invert(2 * y1, p)) % p
            x3 = (k * k - x1 - x2) % p
            y3 = (k * (x1 - x3) - y1) % p
            return int(x3), int(y3)
    else:
        k = ((y2 - y1) * invert(x2 - x1, p)) % p
        x3 = (k * k - x1 - x2) % p
        y3 = (k * (x1 - x3) - y1) % p
        return int(x3), int(y3)

def ECCmul(k, P, p, a):
    Q = (-1, -1)
    while k > 0:
        if(k % 2 == 1):
            if(Q[0] == -1):
                Q = P
            else:
                Q = ECCadd(Q, P, p, a)
        P = ECCadd(P, P, p, a)
        k = k >> 1
    return Q
```

例题

```python
# 已知椭圆曲线加密Ep(a,b)参数为
p = 15424654874903
a = 16546484
b = 4548674875
G(6478678675,5636379357093)
# 私钥为
k = 546768
# 求公钥K(x,y)
```

固然可以用上面的去自定义运算，但为了熟悉$Sagemath$，这里用$Sage$进行示范。

```Sage
p = 15424654874903
a = 16546484
b = 4548674875
E = EllipticCurve(GF(p), [a, b])		# 定义一般椭圆曲线,p为模数,GF为域
G = E(6478678675,5636379357093)			# 以定义好的曲线E包裹,使得G在曲线上运算
k = 546768
k*G					# (13957031351290 : 5520194834100 : 1),G在曲线上,运算也在曲线上

G.order()			# 算出G这个点的阶,阶概念会在抽代中出现,可以搜索乘法阶加以了解
					# 在曲线中便是多少次自加运算可以使这个点到达无穷远点
```

上面是常用形式的椭圆曲线在$Sage$中定义方法，而对于一般形式的椭圆曲线
$$
Y^2+a_1XY+a_3Y=X^3+a_2X^2+a_4X+a_6\\
E: Y^2 = X^3 + 486662X^2 + X, p: 2^{255} - 19
$$

```Sage
# Sage
p = 2**255 - 19
E = EllipticCurve(GF(p), [0, 486662, 0, 1, 0]) # 列表[a,b]替换成五个参数
```

可以看出参数分别对应一般方程中的$[a_1,a_2,a_3,a_4,a_6]$

## 阶(order)

在代数上，使得$a^k\equiv1(mod\ p)$的最小的$k$称为$a$在模$p$下的乘法阶。而在椭圆曲线中，使得$kG=0$最小的$k$称为$G$的阶。例如拿上方例题的数据，$G.order()$便是求$G$点阶的函数，准确数值为$7712323996549$，将这个值与$G$进行乘法运算，得到结果$(0 : 1 : 0)$。这在代数运算中便是无穷远点。阶并不一定是质数，但阶并不超过模$p$，例如$7712323996549$这个点可以看作$353\cdot691\cdot31617863$，那么使得$353G$为$0$的$k$是$691\cdot31617863$。即如果$G$前面的系数是阶的因数，那么所得点的阶也在变化，如果与阶互素，那么变化点的阶不变。$2G$点的阶仍是$7712323996549$。在$RSA$中有逆元的概念，那么也可以将逆元概念应用在椭圆曲线中。但形式会变化成$ed\equiv1(\mod G.order)$
$$
ed-1=k\cdot order\Rightarrow ed\cdot G=(1+k\cdot order)G=(1+0)\cdot G=G
$$
例题(改编自2023台州赛)

```Sage
#Sage
from secret import flag
from Crypto.Util.number import *
p = 64141017538026690847507665744072764126523219720088055136531450296140542176327
a = 20044067980633340889846145545022738789538506162527517230166078217543919426632
b = 26057288374823343156799989208529560426400058011285772399215901682807095239945
E = EllipticCurve(GF(p), [a, b])
G = E.lift_x(bytes_to_long(flag))		# 将特定值作为x,如果该点落在曲线上则输出此点,否则报错
k = 65537
print(k*G)
# (55850738148420090729242491594629261460716908124778407787001788468265293764450,1967879974775574872922342794249035146162245407552933062199883754096387133941)
```

一条椭圆曲线是在射影平面上满足维尔斯特拉斯方程(Weierstrass)所有点的集合
$$
Y^2Z+a_1XYZ+a_3YZ^2=X^3+a_2X^2Z+a_4XZ^2+a_6Z^3
$$


椭圆曲线普通方程
$$
y^2+a_1xy+a_3y=x^3+a_2x^2+a_4x+a_6\\
F_x(x,y)=a_1y-3x_2-2a_2x-a_4\\
F_y(x,y)=2y+a_1x+a_3\\
k=-\frac{F_x(x,y)}{F_y(x,y)}=\frac{3x^2+2a_2x+a_4-a_1y}{2y+a_1x+a_3}
$$
关于Sage将立方曲线转换为椭圆曲线

```Sage
sage: R.<x,y,z> = QQ[];
sage: F = x^3 + y^3 + z^3 - 3*x^2*(y+z) - 3*y^2*(z+x) - 3*z^2*(x+y) - 5*x*y*z;
sage: WeierstrassForm(F)
(-11209/48, 1185157/864)
```

[常见曲线](https://www.hyperelliptic.org/EFD/)，[一个有趣的等式](https://mlzeng.com/an-interesting-equation.html)

## DSA:数字签名算法(Digital Signature Algorithm)

给定一个群$(G,\cdot)$的生成元$g$，生成私钥$x$并且由此计算公钥$a=g^x$(即为$x$个$g$做$\cdot$运算)。对输入信息$m$的签名过程如下：

1. 算出$m$的哈希$H(m)$
2. 生成一个随机数$k$满足$0<k<|G|$
3. 求出$b=g^k$
4. 求出$r=f(b)$，其中$f$是一个公开的函数
5. 求出$s=k^{-1}(H(m)+rx)\mod |G|$
6. 消息$m$的签名为$(r,s)$

得到消息$m$以及其签名$(r,s)$，则验签过程如下：

1. 先求出消息m的哈希$H(m)$
2. 计算$u_1=s^{-1}H(m)\mod |G|$
3. 计算$u_2=s^{-1}r\mod\ |G|$
4. 计算$b'=g^{u_1}\cdot a^{u_2}$
5. 求出$r'=f(b)$
6. 如果$r'=r$，则签名有效，否则无效

#### 例题：signuature

```python
import ecdsa
import random
 
def ecdsa_test(dA,k):
 
    sk = ecdsa.SigningKey.from_secret_exponent(
        secexp=dA,
        curve=ecdsa.SECP256k1
    )
    sig1 = sk.sign(data=b'Hi.', k=k).hex()
    sig2 = sk.sign(data=b'hello.', k=k).hex()
 
    r1 = int(sig1[:64], 16)
    s1 = int(sig1[64:], 16)
    s2 = int(sig2[64:], 16)
    return r1,s1,s2
 
if __name__ == '__main__':
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    a = random.randint(0,n)
    flag = 'flag{' + str(a) + "}"
    b = random.randint(0,n)
    print(ecdsa_test(a,b))
 
# (4690192503304946823926998585663150874421527890534303129755098666293734606680, 111157363347893999914897601390136910031659525525419989250638426589503279490788, 74486305819584508240056247318325239805160339288252987178597122489325719901254)
```

DSA签名，算法如下，实际上`n`是曲线的阶，题目直接给出了，题目曲线是

```
CurveFp(p=115792089237316195423570985008687907853269984665640564039457584007908834671663, a=0, b=7, h=1)
```

在`sage`中可以定义看阶，与n相同
$$
s=k^{-1}(H(m)+rx)(mod\ n)
$$
传入`(a,b)`代替`(x,k)`，那么两个式子可以写成
$$
s_1\equiv b^{-1}(h_1+r_1a)\mod n\\
s_2\equiv b^{-1}(h_2+r_2a)\mod n\\
t=\frac{s_1}{s_2}\equiv\frac{h_1+r_1a}{h_2+r_2a}\mod n\\
h_1+r_1a\equiv t(h_2+r_2a)
$$
因为传入的`x`相同，那么经过`x`特定运算的`r`也相同，式子可以恢复成
$$
a\equiv(r_1-tr_1)^{-1}(th_2-h_1)\mod n
$$

```
from Crypto.Util.number import *
from hashlib import sha1
r1, s1, s2 = (4690192503304946823926998585663150874421527890534303129755098666293734606680, 111157363347893999914897601390136910031659525525419989250638426589503279490788, 74486305819584508240056247318325239805160339288252987178597122489325719901254)
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
h1 = int(sha1(b'Hi.').hexdigest(), 16)
h2 = int(sha1(b'hello.').hexdigest(), 16)
t = s1*inverse(s2, n) % n
a = inverse(r1 - t*r1, n) * (t*h2 - h1) % n
print(a)
```

## ECDSA

基点$G$，曲线阶为$n$，随机选取$d_A$作为私钥，$Q_A=d_AG$，发送信息$m$
$z=hash(m)$，随机选取$k(nonce)\in(1,n-1)$，计算$(x_1,y_1)=kG$，$r=x_1(mod\ n)$，$s=k^{-1}(z+rd_A)(mod\ n)$，输出签名$(r,s)$

## 三类曲线

### 爱德华曲线(Edwards curves)

曲线方程：$x^2+y^2=1+dx^2y^2$，或者一般形式：$x^2+y^2=c^2(1+dx^2y^2)$

与`Weierstrass`曲线上的点群一样，爱德华曲线上的点也构成一个交换群，点与点可以相加，标量相乘。为方便运算，以下使用都是第一类方程形式。
$$
(x_1,y_1)+(x_2,y_2)=(\frac{x_1y_2+x_2y_1}{1+dx_1x_2y_1y_2},\frac{y_1y_2-x_1x_1}{1-dx_1x_2y_1y_2})
$$
点$(x_1,y_1)$的逆是$(-x_1,y_1)$，群内"零元"表示为$(0,1)$，又称为"中性点"。关于零元的运算$P+(0,1)=P,P+(-P)=(0,1)$。

当两个点相同时，公式能进一步处理，即代入原方程:
$$
2(x_1,y_1)=(\frac{2x_1y_1}{1+dx_1^2y_1^2},\frac{y_1^2-x_1^2}{1-dx_1^2y_1^2})\\ \quad\quad\quad\ =(\frac{2x_1y_1}{x_1^2+y_1^2},\frac{y_1^2-x_1^2}{2-x_1^2-y_1^2})
$$

### 扭曲爱德华曲线(Twisted Edwards curves)

[具体详解参考](http://blog.tolinchan.xyz/2022/10/31/%e6%89%ad%e6%9b%b2%e7%88%b1%e5%be%b7%e5%8d%8e%e6%9b%b2%e7%ba%bf/)

方程:
$$
ax^2+y^2=1+dx^2y^2(a,d\neq0且a\neq d)
$$
扭曲爱德华曲线方程多了一个系数$a$，相对应的点加法运算有变化：
$$
(x_3,y_3)=(x_1,y_1)+(x_2,y_2)=(\frac{x_1y_2+x_2y_1}{1+dx_1x_2y_1y_2},\frac{y_1y_2-ax_1x_2}{1-dx_1x_2y_1y_2})
$$
如果两个相同点相加公式变为：
$$
(x_3,y_3)=2(x_1,y_1)=(\frac{2x_1y_1}{ax_1^2+y_1^2},\frac{y_1^2-ax_1^2}{2-ax_1^2-y_1^2})
$$

### 曲线相互变换

维尔斯特拉斯：$y^2=x^3+ax+b\quad\Delta=4a^3+27b^2\neq0$
蒙哥马利：		$Kt^2=s^3+Js^2+s$
扭曲爱德华：	$av^2+w^2=1+dv^2w^2$

相互转换规则：
$$
\begin{align}
\mathbf{1}.\quad&Kt^2=s^3+Js^2+s\xrightarrow[b=\frac{2J^3-9J}{27K^3}]{a=\frac{3-J^2}{3K^2}}y^2=x^3+ax+b\\
&\qquad(s,t)\xrightarrow[y=\frac{t}{K}]{x=\frac{3s+J}{3K}}(x,y)\qquad(x,y)\xrightarrow[t=yK]{s=\frac{3Kx-J}{3}}(s,t)\\\\
\mathit{2}.\quad&av^2+w^2=1+dv^2w^2\xrightarrow[K=\frac{4}{a-d}]{J=\frac{2(a+d)}{a-d}}Kt^2=s^3+Js^2+s\\
&\qquad(v,w)\xrightarrow[t=\frac{1+w}{(1-w)v}=\frac{s}{v}]{s=\frac{1+w}{1-w}}(s,t)\qquad v=0\mid w=1\rightarrow(s,t)=(0,0) \\
&\qquad(s,t)\xrightarrow[w=\frac{s-1}{s+1}]{v=\frac{s}{t}}(v,w)\qquad t=0\mid s=1\rightarrow(v,w)=(0,-1)
\end{align}
$$

## 攻击和例题

### wiener's attack

先复习下在$RSA$中的维纳斯攻击
$$
ed\equiv1(mod\ \varphi(N)),\ d<\frac{1}{3}N^{\frac{1}{4}}\\
|\frac{e}{N}-\frac{k}{d}|<\frac{1}{2d^2}
$$
在$RSA$关于$wiener's$的核心攻击算法中，将$k,d$看作是$e,n$的某个渐进分数，通过构造$\frac{e}{n}$的形式渐进得出$\frac{k}{d}$，如若满足$(ed-1)\% k$的形式，便能说$ed-1=kn$。即能还原出$k,d$，而除了最上方的算渐进式，下面是无需用到$n$这个式子的。

```
fra = continued_fraction(e/n)
for i in range(1, len(fra)):
    k = fra.numerator(i)
    d = fra.denominator(i)
    if (e*d-1)%k == 0:
            print(k, d)
```

题目

```Sage
# Sage
import os
import random
from Crypto.Util.number import *
from secret import flag

assert flag[:7]==b'DASCTF{' and flag[-1:]==b'}'
flag = flag[7:-1]
m = bytes_to_long(flag)

def magic_rsa(m):
    p = getPrime(384)
    q = getPrime(384)
    Fp = GF(p)
    Fq = GF(q)
    n = p*q
    d = getPrime(80)
    a = random.randint(0, p-1)
    b = random.randint(0, p-1)
    
    Ep = EllipticCurve(Zmod(p), [a, b])
    Eq = EllipticCurve(Zmod(q), [a, b])
    En = EllipticCurve(Zmod(n), [a, b])
    ord_p = Ep.order()
    ord_q = Eq.order()
    e = inverse_mod(d, ord_p*ord_q)

    xm = bytes_to_long(m+os.urandom(16))
    while True:
        try:
            Gp = Ep.lift_x(Fp(xm))
            Gq = Eq.lift_x(Fq(xm))
            ym = crt([int(Gp.xy()[1]),int(Gq.xy()[1])],[p,q])
            break
        except :
            xm += 1
            continue
           
    M = En((xm,ym))
    C = e*M
    pk = [a, b, n, e, C.xy()]
    return pk

print(magic_rsa(flag))
"""
[10517482889776460226798449006280081167663671198448544453304563030553066300585088657159799516828057458092448853052920, 10402402380108575947733278581108880071660185906203575453837669489513650182676772750843558327746184945922314875098996, 452239510514900186933709062848646640558105660312444312121851933676754687850508865659206624803226663304812888272594694285123823218948165607478144589871322148031514596122654196640778853480169180864412134209693877604844174450602155353, 137939931394124279393027766586199451754893501053862574760060288577053514723631473985259186063729745515767167268309839903521149677958518517988564142828176577685619561913731155508981456507557881596602396073589127827579264760182112015, (312312975924665463422872243489714243976133330669934414246404507993066820310886215600585539115436654843078716170526368558972800117033427241194242498913898005160762151892979826292737941332916578310350510245475526522735894588645243659, 422891099305786578397746684898210811095359530216631541482542541898542508551347882962281401572399110483550691802487377837504493122807091311281569558317360479103461652558448871769150783477147866528115922507893061101403528629595165327)]
"""
```

可以看到$n$并非质数，在椭圆曲线中，只有模数是质数才能用$order$函数，非质数则会报错，不信可以试试。$ordn=ordp\cdot ordq$，$ed\equiv1(mod\ ordn)$。题目中$d$只有$80bits$，满足$d<\frac{1}{3}N^{\frac{1}{4}}$，那么可以类推将$k,d$看作是椭圆曲线中$e,n$的某个渐进分数，这样可以使用$wiener$恢复$d$。

```Sage
E = EllipticCurve(Zmod(n), [a, b])		# 非质数便不能用GF,只能用普通模Zmod
C = E(C)
O = E(0, 1, 0)
fra = continued_fraction(e/n)
for i in range(1, len(fra)):
	k = fra.numerator(i)
    d = fra.denominator(i)
    if C*(e*d - 1) == O and d != 1:
        print(d)
        break
```

### Smart's attack

```python
p = 
A = 
B = 
E = EllipticCurve(GF(p),[A,B])
P = E(,)
Q = E(,)
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

r = SmartAttack(P, Q, p)
print(r)
```



### [第五空间 2021]ecc

```python
print 'Try to solve the 3 ECC'

from secret import flag
from Crypto.Util.number import *
assert(flag[:5]=='flag{')
flag = flag[5:-1]
num1 = bytes_to_long(flag[:7])
num2 = bytes_to_long(flag[7:14])
num3 = bytes_to_long(flag[14:])

def ECC1(num):
	p = 146808027458411567
	A = 46056180
	B = 2316783294673
	E = EllipticCurve(GF(p),[A,B])
	P = E.random_point() 
	Q = num*P
	print E
	print 'P:',P
	print 'Q:',Q

def ECC2(num):
	p = 1256438680873352167711863680253958927079458741172412327087203
	#import random
	#A = random.randrange(389718923781273978681723687163812)
	#B = random.randrange(816378675675716537126387613131232121431231)
	A = 377999945830334462584412960368612
	B = 604811648267717218711247799143415167229480
	E = EllipticCurve(GF(p),[A,B])
	P = E.random_point() 
	Q = num*P
	print E
	print 'P:',P
	print 'Q:',Q
	factors, exponents = zip(*factor(E.order()))
	primes = [factors[i] ^ exponents[i] for i in range(len(factors))][:-1]
	print primes
	dlogs = []
	for fac in primes:
		t = int(int(P.order()) / int(fac))
		dlog = discrete_log(t*Q,t*P,operation="+")
		dlogs += [dlog]
		print("factor: "+str(fac)+", Discrete Log: "+str(dlog)) #calculates discrete logarithm for each prime order
	print num
	print crt(dlogs,primes)



def ECC3(num):
	p = 0xd3ceec4c84af8fa5f3e9af91e00cabacaaaecec3da619400e29a25abececfdc9bd678e2708a58acb1bd15370acc39c596807dab6229dca11fd3a217510258d1b
	A = 0x95fc77eb3119991a0022168c83eee7178e6c3eeaf75e0fdf1853b8ef4cb97a9058c271ee193b8b27938a07052f918c35eccb027b0b168b4e2566b247b91dc07
	B = 0x926b0e42376d112ca971569a8d3b3eda12172dfb4929aea13da7f10fb81f3b96bf1e28b4a396a1fcf38d80b463582e45d06a548e0dc0d567fc668bd119c346b2
	E = EllipticCurve(GF(p),[A,B])
	P = E.random_point() 
	Q = num*P
	print E
	print 'P:',P
	print 'Q:',Q

ECC1(num1)
print '=============='
ECC2(num2)
print '=============='
ECC3(num3)
```

关于`discrete_log`，上面$P$是基点，$Q$是运算后的点，可通过`P.discrete_log(Q)`算出数乘`num`，得到为`13566003730592612`，用`num*P==Q`进行验证，就是`True`

out

```
Try to solve the 3 ECC
Elliptic Curve defined by y^2 = x^3 + 46056180*x + 2316783294673 over Finite Field of size 146808027458411567
P: (119851377153561800 : 50725039619018388 : 1)
Q: (22306318711744209 : 111808951703508717 : 1)
==============
Elliptic Curve defined by y^2 = x^3 + 377999945830334462584412960368612*x + 604811648267717218711247799143415167229480 over Finite Field of size 1256438680873352167711863680253958927079458741172412327087203
P: (550637390822762334900354060650869238926454800955557622817950 : 700751312208881169841494663466728684704743091638451132521079 : 1)
Q: (1152079922659509908913443110457333432642379532625238229329830 : 819973744403969324837069647827669815566569448190043645544592 : 1)
==============
Elliptic Curve defined by y^2 = x^3 + 490963434153515882934487973185142842357175523008183292296815140698999054658777820556076794490414610737654365807063916602037816955706321036900113929329671*x + 7668542654793784988436499086739239442915170287346121645884096222948338279165302213440060079141960679678526016348025029558335977042712382611197995002316466 over Finite Field of size 11093300438765357787693823122068501933326829181518693650897090781749379503427651954028543076247583697669597230934286751428880673539155279232304301123931419
P: (10121571443191913072732572831490534620810835306892634555532657696255506898960536955568544782337611042739846570602400973952350443413585203452769205144937861 : 8425218582467077730409837945083571362745388328043930511865174847436798990397124804357982565055918658197831123970115905304092351218676660067914209199149610 : 1)
Q: (964864009142237137341389653756165935542611153576641370639729304570649749004810980672415306977194223081235401355646820597987366171212332294914445469010927 : 5162185780511783278449342529269970453734248460302908455520831950343371147566682530583160574217543701164101226640565768860451999819324219344705421407572537 : 1)
```

### [HITCTF 2021]baby_ecc

```python
#Elliptic Curve: y^2 = x^3 + 7 mod N which is secp256k1
N = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
E = EllipticCurve(GF(N), [0, 7])
xG = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
yG = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = (xG,yG)
n = [secret0,secret1,secret2]
#flag = "HITCTF2021{"+''.join([hex(i) for i in n])
for i in n:
    assert i<1048575
    print(i*G)
cipher0 = (76950424233905085841024245566087362444302867365333079406072251240614685819574 , 85411751544372518735487392020328074286181156955764536032224435533596344295845)
cipher1 = (42965775717446397624794967106656352716523975639425128723916600655527177888618 , 32441185377964242317381212165164045554672930373070033784896067179784273837186)
cipher2 = (26540437977825986616280918476305280126789402372613847626897144336866973077426 , 1098483412130402123611878473773066229139054475941277138170271010492372383833)

assert n[0]*G == cipher0
assert n[1]*G == cipher1
assert n[2]*G == cipher2

#Find n and recover the flag. Good luck!
```

`sagemath`内的`bsgs`函数不知道为什么不在内置范围内，需要导入，查阅官方资料时也看到一个新的语法，G是落在曲线上任意一点，`parent`自然是所属曲线，再加上`(0)`参数便是无穷远点的表示

```
G.parent()(0)
Hasse_bounds(i)
```



```python
from sage.groups.generic import bsgs
N = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
E = EllipticCurve(GF(N), [0, 7])
i = 1048575
G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
c0 = E(76950424233905085841024245566087362444302867365333079406072251240614685819574 , 85411751544372518735487392020328074286181156955764536032224435533596344295845)
c1 = E(42965775717446397624794967106656352716523975639425128723916600655527177888618 , 32441185377964242317381212165164045554672930373070033784896067179784273837186)
c2 = E(26540437977825986616280918476305280126789402372613847626897144336866973077426 , 1098483412130402123611878473773066229139054475941277138170271010492372383833)
s0 = bsgs(G, c0, (0, i), operation='+')
s1 = bsgs(G, c1, (0, i), operation='+')
s2 = bsgs(G, c2, (0, i), operation='+')
```

### [HXP CTF2018 Curve12833227]

在介绍题目前，先看[这篇](https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp)，给定一条曲线

$$
E:y^2=x^3+17230x+22699\mod 23981\\
G = (1451, 1362),\quad dG=(3141,12767)
$$
需要求出`d`，通过计算发现$\Delta\equiv-16(4a^3+27b^2)\equiv0\mod p$，这是一条奇异曲线，此类曲线是无法在`sage`中直接用函数定义的，通过分解曲线方程发现是`node`形式的`singular curve`
$$
y^2=(x-\alpha)^2(x-\beta)
$$

> 对于singular curve来说，其分两种情况cusp和node，其中cusp指椭圆曲线方程有三重根，而node指有两重根。也就是说他们方程分别可以写成如下形式：
> $$
> y^2=x^3\\y^2=(x-\alpha)^2(x-\beta)
> $$

而两种形式的`singular curve`都存在不同方式的数域映射，对于`node`而言是：
$$
E\mapsto F_p:(x,y)\mapsto\frac{y+\sqrt{\alpha-\beta}(x-\alpha)}{y-\sqrt{\alpha-\beta}(x-\alpha)}
$$
所以可以映射到$F_p$下求数域的`dlp`，并且`p-1`光滑

> 当$\alpha-\beta$并不是模p下的二次剩余时，这个映射需要指向$F_{p^2}$，会多一个p+1的子群



回头看题目，找到多项式零点$(23796,0)$，通过改变变量$(x,y)\mapsto(x-23796,y-0)$，那么可以将曲线写成
$$
y^2=x^3+23426x^2=(x+23426)x^2
$$
改写后可看出这不是cusp，而是node，node可映射至乘法群$F_{23981}^*$，$(x+23426)$可再次分解，$23426\equiv 7020^2\mod p$
$$
(x,y)\mapsto\frac{y+7020x}{y-7020x}
$$

```python
p = 23981
P.<x> = GF(p)[]
f = x^3 + 17230*x + 22699
P = (1451, 1362)
Q = (3141, 12767)
# change variables to have the singularity at (0,0)
f_ = f.subs(x=x + 23796)
P_ = (P[0] - 23796, P[1])
Q_ = (Q[0] - 23796, Q[1])
# show that the curve is of the form y^2 = x^3 + x^2
f_.factor()	# (x + 23426) * x^2
t = GF(p)(23426).square_root()
# map both points to F_p
u = (P_[1] + t*P_[0])/(P_[1] - t*P_[0]) % p
v = (Q_[1] + t*Q_[0])/(Q_[1] - t*Q_[0]) % p
# use Sage to solve the logarithm
discrete_log(v, u)
```



题目的源码先搁着，首先是从[这里](https://ecc.danil.co/tasks/singular/)找到的$\Delta=0$时的解法，首先在$\Delta=0$的情况下，曲线与乘法群之间存在同构关系，可以借助域的解法实现`dlp`运算

1. $y^2=x^3$

    曲线与$F_p$同构

2. $y^2=x^2*(x-1)$

    曲线与$F_{p^2}^*$同构

$$
y^2\equiv x^3+2x^2+x\equiv x(x+1)^2
$$

可以找到零点`-1`，那么可以改写成
$$
y^2\equiv (x-1)x^2
$$


曲线是
$$
y^2=x^3+2x^2+x=x(x+1)^2
$$
找零点$(-1,0)$，再进行`dlp`运算

```python
p = 2^128 - 33227
P.<x> = GF(p)[]
f = x^3 + 2*x^2 + x
P = (4, 10)
Q = (104708042197107879674895393611622483404, 276453155315387771858614408885950682409)

f_ = f.subs(x=x-1)
print(f_.factor()) # 340282366920938463463374607431768178228

P_ = (P[0] +1, P[1])
Q_ = (Q[0] +1, Q[1])

t = GF(p)(340282366920938463463374607431768178228).square_root()
u = (P_[1] + t*P_[0])/(P_[1] - t*P_[0]) % p
v = (Q_[1] + t*Q_[0])/(Q_[1] - t*Q_[0]) % p

print(v.log(u))
```

### [2024XYCTF]easy_ecc

题目定义的蒙哥马利曲线，需要先将其转换，得到

```python
a = 1098066776930223927329092382214459309226361965213
b = 1263248714105743124314734095577181018742053879965591734
```

$$
y^2=x^3+ax+b
$$

```python
a = 1098066776930223927329092382214459309226361965213
b = 1263248714105743124314734095577181018742053879965591734
p = 1365855822212045061018261334821659180641576788523935481
R.<x> = PolynomialRing(GF(p))
f = x**3 + a*x + b
f.roots()
x1 = 1088514544906132155907102721251063316971086679731277828
x2 = 821598549758978983064709974196127522156033448658296567
f_ = f.subs(x-x2)
print(f_.factor())

P = (804603363012007759329983017410816754946539644939, 668360700828957783980888938878566241242911721895008218)
Q = (933414165833077907509715600260551365988944141925739220, 121346737700219338084994830488363509910434835223666824)
P_ = (P[0] + x2, P[1])
Q_ = (Q[0] + x2, Q[1])

t = GF(p)(821598549758978983064709974196127522156033448658296567).square_root()
u = (P_[1] + t*P_[0])/(P_[1] - t*P_[0]) % p
v = (Q_[1] + t*Q_[0])/(Q_[1] - t*Q_[0]) % p
```

https://www.cnblogs.com/tr0uble/p/17114187.html#/c/subject/p/17114187.html

https://blog.sww.moe/post/x25519/

直接照搬上面的式子是不行的，因为本题并不能化成如下形式
$$
y^2=(x+\alpha)^2x
$$
根据完整的映射公式可以得到正解

```python
alpha = -544257272453066077953551360625531658485543339865638914
beta = -277341277305912905111158613570595863670490108792657653

def map(x, y):
    r = F(alpha - beta).sqrt()
    t = F(r * (x - alpha))
    return F((y + t) / (y - t))
```

