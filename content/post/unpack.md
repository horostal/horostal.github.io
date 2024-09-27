---
date: "2024-07-31"
title: unpack some game
---
就单纯解包玩玩，没有一点关于游戏引擎的了解。

## UE4

最先解包的是`UE4`游戏，刚好有`Wuthering Waves`，就想着提取模型试试。首先`UE4`游戏用[Umodel](https://www.gildor.org/en/projects/umodel#files)解包，对于某些游戏[fmodel](https://fmodel.app/)有专门版本，鸣潮也是，解包目录在pc端是`Wuthering Waves\Wuthering Waves Game\Client\Content\Paks`，底下的`.pak`文件就是资源包，导入时会提示需要`AES`密钥，很多`UE4`游戏的密钥都可以在[这个网站](https://cs.rin.ru/forum/viewtopic.php?f=10&t=100672)找到。鸣潮和尘白的密钥在里面都找到了，如果没有，在网站的`How to dump exe for protected games`栏目下是自提取密钥方法，工具链接需要登录才能看到，首先是工具[AES_finder](https://cs.rin.ru/forum/download/file.php?id=112835)，但对`Wuthering Waves.exe`直接使用无效，因为`exe`文件开了保护，甚至开着`x64dbg`连游戏都无法启动，文中的另一个工具[Process Hacker](https://processhacker.sourceforge.io/downloads.php)可以用，管理员启动后可以`dump`出`exe`文件数据，将数据修改成`exe`后缀，与`AES_finder`同目录时运行`AES_finder`稍等数分钟会出现`key.txt`，里面写着`0x……`便是提取成功，至少试过鸣潮和尘白都能用这种方法提取。

## Unity

`Unity`开发的游戏才是真的多，绝大多数热门手游都是`unity`，而解`unity`游戏需要用到[AssetStudio](https://github.com/Perfare/AssetStudio)，这是最早开发者，项目已经不更新了，对于新的`unity`版本和`unityCN`（中国`unity`加密）无法解包，这时候用到Razmoth佬的[CNStudio](https://github.com/Razmoth/CNStudio)，

`CNStudio`的`Options`栏目下会有`Specify UnityCN key`，里面有不少游戏的`key`，战双帕弥什、恋与深空、花亦山心之月，只要点名字左侧空白处两下就是选择此游戏的`key`，接下来只要导入包就行。![1723785832621](https://s2.loli.net/2024/08/16/XDTNLVFAxa4l812.png)

解包后的导出选项也有讲究，`Options`里面最后一栏`Export options`就是导出设置，修改下`Group exported assets by`就行，默认是`type name`按照`type`进行分类，同`type`放入同个文件夹，提取`cg`方便，但提取模型时就不是很好，动作模型需要将贴图、骨骼文件放在一起才会生效，改成`container path`就能按照源目录导出，将文件按照源目录分类。

就所解包过的游戏来看，spine文件(就是那些动作模型)一般分为`json`结构和`skel`结构：

```
json
xxxxx.json
xxxxx.atlas
xxxxx.png

skel
xxxxx.skel
xxxxx.atlas
xxxxx.png
```

两种形式文件都可以用[Skeleton Viewer](https://zh.esotericsoftware.com/spine-skeleton-viewer)查看，但一般名字都不会直接如此，`atlas`可能变成`atlas.prefab`，`json`则是`prefab`，扔进十六进制看看是`json`还是`skel`，带有非常多括号的就是`json`形式，但不管哪种格式都有`spine`的版本，必须用对应版本的工具才能打开，这也是为什么不推荐`Spine Pro`的原因，目前广泛流通(破解)的就是`Spine Pro 3.8.75`，而且还不能切换版本；导入时只需要选择`xxxxx.json`或`xxxxx.skel`即可，工具会自动导入同目录贴图。

![1723791861431](https://s2.loli.net/2024/08/16/8eTEIhlpALB3bt6.png)



还有重命名问题，写个`python`

```python
import os
path = "com.jtw.takuxi/output/"

for x, y, z in os.walk(path):
    # print(x, y, z)
    if len(z):
        for i in z:
            tmp = i.replace("atlas.prefab", "atlas").replace("prefab", "json")
            os.rename(x + '/' + i, x + '/' + tmp)

```

`walk`函数真好用，完全不用自己考虑递归，函数内会自动向下递归，`x`表示当前目录，`y`表示下面的子目录，`z`则是当前目录的文件。

### HBR

`HBR`大部分资源在`steamapps\common\HeavenBurnsRed\HeavenBurnsRed_Data\StreamingAssets`，目录下`aa`是`bundle`文件，而`Sound`意如其名，音视频文件。

少部分资源位于`%USER_HOME%\AppData\LocalLow\Unity\wfs_HeavenBurnsRed`，例如其画廊内的`cg`全为此，此为`pc`端游戏路径，包未加密，拖入AS即可。

音视频文件解密反而寻不到大量教程，花些时间去探究，首先是文件格式，存在`awb`、`acb`、`usm`三种格式文件，其中`awb`、`acb`是音频文件，文件头分别是`AFS2`、`@UTF`，而`usm`是视频文件，文件头是`CRID`；`awb`和`acb`都可以用`foobar2000`播放，需要先安装插件`vgmstream `，另外还可以播放`hca`文件，插件直接去下[foo_input_vgmstream](https://github.com/vgmstream/vgmstream/releases/tag/r1951)，之后用foobar打开插件安装即可；关于`hca`文件密钥，同时也是`usm`文件密钥，可以看[kawashima](https://blog.mottomo.moe/categories/Tech/RE/zh/2018-10-12-New-HCA-Encryption/)大佬文章，同时很多游戏密钥也可以在[hca_keys](https://github.com/vgmstream/vgmstream/blob/master/src/meta/hca_keys.h)里找到，`HBR`密钥是`6615518E8ECED447`，原先是明文放在`HeavenBurnsRed\HeavenBurnsRed_Data\resources.assets`文件中的，`2024-9-21`更新后将其隐藏，但密钥没换，可以继续解`usm`，用`crid_mod`程序解`usm`，使用方法参考[这里](https://github.com/bnnm/vgmstream/wiki/usmkey)。

```bash
crid_mod.exe -b 6615518E -a 8ECED447 -v -x -i 0D8DE04866AFBC79C7C89784F7CF16B1
```

对此可以先将原路径下`usm`文件全部选出来，因为没有后缀只能依次读取

```python
import os
path = r'D:\SteamLibrary\steamapps\common\HeavenBurnsRed\HeavenBurnsRed_Data\StreamingAssets\Sound/'
output = r'D:\game\HBR/'
for i in os.listdir(path):
    f = open(path+i, 'rb').read()
    if f.startswith(b'CRID'):
        # print(i)
        out = open(output+i, 'wb')
        out.write(f)
        out.close()
```

再写个bat脚本对文件依次解密，程序路径和相对路径换下就行，解出来对应有`adx`、`m2v`、`ini`三种文件似乎没啥用直接在bat里删了，`adx`是视频音轨可以用`foobar`播放，`m2v`是解出视频文件，`VLC`就能播放，还有网上推荐的`PotPlayer`也可以，但`windows`原生播放器无法识别。

```bat
@echo off
set key=6615518E8ECED447
set program="D:\Program Files\unpack\CRID(.usm)Demux Tool v1.02-mod\crid_mod.exe"
for /r %%a in (HBR\*) do call %program% -b %key:~0,8% -a %key:~8,15% -v -x -c  %%a & ffmpeg -i %%a.m2v -i %%a.adx.wav -c:v copy -map 0:v -map 1:a -y %%a.mp4
pause
```

### 安卓抓包

有些游戏角色好感度上去，解锁剧情才会下载所需要的包，这时候可以通过抓包看看里面有哪些数据，约等于直接通过。

首先尝试的就是`Fiddler`工具，但是模拟器的浏览器走了代理，部分软件没走，因此没抓到软件的流量包，游戏还一直卡在登录界面，验证都过不去；

![1723792818586](https://s2.loli.net/2024/08/16/Hyx2aOVvfdJKsSp.png)换成[Reqable](https://reqable.com/zh-CN/)就完美解决了，这软件证书安装还跟`Fiddler`不同，直接是`.0`这种文件而不是`.cer`，只要能将证书`push`进去就行，某种意义上说只需要执行第四条指令即可，因为逍遥模拟器里面没有`avbctl`，第二条指令就直接无法执行，这影响到第三条`remount`，没有经过`remount`会提示`Read-only file system`；但实际上只要改下模拟器设置就行，把共享系统盘改成独立系统盘就能`remount`。

![1723793098265](https://s2.loli.net/2024/08/16/SFWZyT6OgxdK9Yl.png)

模拟器端与电脑端互联后可以在电脑上抓包，具体操作工具里面讲得很清楚，先下个剧情试试，会发现在上剧情前去访问了一个文件`Android.size.json`，放浏览器上下载后打开就是资源目录，包括后面没解锁的剧情都在里面，这游戏是这文件，但其他游戏不一定，譬如`DMM オトギフロンティア `资源清单是`AdditionalAssets.csv`。接下来拿取资源可以参考[这里](https://live2dhub.com/t/topic/3454)。

![1723793311106](https://s2.loli.net/2024/08/16/F1pX8MhEWn2GbKk.png)
