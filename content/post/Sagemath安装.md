---
date: "2024-04-15"
title: Sagemath安装
---
### Sagemath安装

`Sagemath`各版本简要信息：https://wiki.sagemath.org/ReleaseTours/

`github`项目：https://github.com/sagemath/sage/

`aliyun`镜像：https://mirrors.aliyun.com/sagemath/src/

图便捷可下`exe`(仅支持到`9.3`)：https://mirrors.aliyun.com/sagemath/win/index.html

#### docker

有`docker`环境可选择装在`docker`上，执行以下指令即可。

```
docker pull sagemath/sagemath
```

启动`docker`之后在`cmd/PowerShell`中输入`docker run -it sagemath/sagemath`，即可使用。`docker`里的`sage`镜像内置`jupter`，可以通过网页使用。

```
docker run -p8888:8888 sagemath/sagemath sage-jupyter
```

终端会出现带`token`的`URL`，将其放入浏览器`URL`栏即可。

#### Linux集成库安装

很多源可能没有`sagemath`的包，直接`apt`找不到需要换源，下面是一个可用源，国外源记得提速。

```
echo 'deb http://deb.debian.org/debian bookworm main contrib non-free' | sudo tee -a /etc/apt/sources.list
sudo apt update
sudo apt -y install sagemath
```
#### Linux conda编译

官网上说编译后的`sage`执行效率比`apt`里的会更高，推荐选择这个最麻烦的方式。

首先需要下载几个工具

- `Miniconda3`：解决依赖问题和环境污染问题的，`Sagemath`好像从9.6后就推荐用`Conda`解决依赖包的问题，然后就下架了`binary`。
- `Mambaforce`：按照官网教程来即可https://doc.sagemath.org/html/en/installation/conda.html
- `SageMath 10.2`的源码

```
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
curl -L -O https://github.com/conda-forge/miniforge/releases/latest/download/Mambaforge-$(uname)-$(uname -m).sh
wget https://mirrors.aliyun.com/sagemath/src/sage-10.2.tar.gz
```

然后`Miniconda3`和`Mambaforce`下载下来的都是安装脚本，直接运行按提示安装。

```
sh Miniconda3-latest-Linux-x86_64.sh
sh Mambaforge-$(uname)-$(uname -m).sh
source ~/.bashrc
conda --version
```

如无意外应该可以运行`conda`了，但终端执行命令会出现个烦人的`(base)`，可以这样解决

```
echo "conda deactivate" >> ~/.bashrc
source ~/.bashrc
```

解压源码包，并进入目录

```
tar xf ./sage-10.2.tar.gz
cd ./sage-10.2
```

在`build`之前先换一下`Conda`的源，创建`~/.condarc`并修改成清华镜像

```
channels:
  - defaults
show_channel_urls: true
default_channels:
  - https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/main
  - https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/r
  - https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/msys2
  - https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge/
custom_channels:
  conda-forge: https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud
  msys2: https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud
  bioconda: https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud
  menpo: https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud
  pytorch: https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud
  simpleitk: https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud
```

安装`Mamba`

```
conda install mamba
mamba --version
```

在`sage-10.2`这个目录下依次执行命令，

```
export SAGE_NUM_THREADS=24
./bootstrap-conda
mamba env create --file src/environment-dev-3.11.yml --name sage-dev
conda activate sage-dev

./bootstrap
pip install --no-build-isolation -v -v --editable ./pkgs/sage-conf ./pkgs/sage-setup
pip install --no-build-isolation -v -v --editable ./src
sage -c 'print(version())'

conda deactivate
```

之后使用`sage`，输入`conda activate sage-dev`，命令行开头弹出`sage-dev`，接着输入`sage`就能进入熟悉的界面。或者进入`cd sage-10.2/`，执行`./sage`。

参考官网文档：https://doc.sagemath.org/html/en/installation/conda.html

#### windows下的sage

https://mirrors.aliyun.com/sagemath/win/index.html

链接中直接下载安装程序，可按照自己需求自定义下载路径，因为直接使用黑框不太美观，而且复制不是用`ctrl+v`，而是`shift+insert`来着（有点忘了），反正不是非常方便，试着用两种方式解决

##### 换窗口达到与Linux下等同效果

找到`Sagemath`这个快捷应用，因为是链接形式，可以看到属性里面有一栏目标，目标中有打开`sage`的指令，对这个目标进行修改，上面是原版的指令，下面是修改后的，可以看到原先调用的是`mintty`，但又通过它调用了`bash`，我们直接调用`bash`，就能达到与`cmd`打开一样的效果

```
D:\scoop\apps\sagemath\current\runtime\bin\mintty.exe -t 'SageMath' /bin/bash --login -c '/opt/sagemath-*/sage'
D:\scoop\apps\sagemath\current\runtime\bin\bash.exe --login -c '/opt/sagemath-*/sage'
```

接下来点击打开还是与`cmd`一样的黑框，但背景与`cmd`不进行共享，可以单独设置，点窗口处的向下箭头，进入设置；滑到最后添加新配置文件，新建空配置文件，名称可以自定义，将命令行修改成`sage`内`bash`的地址，如上面的`D:\scoop\apps\sagemath\current\runtime\bin\bash.exe`，下方的外观内可修改背景图片和透明度，跟`cmd`美化类似，最后达到如下效果，复制也能用`ctrl+v`![1714039564181](https://s2.loli.net/2024/04/25/JvdRLDh2Wtr9g7Y.png)

##### 与vsc的衔接

这个方法实际上是先找到的，参考自https://blog.csdn.net/u010883831/article/details/128262134 ，正因为这篇文章才发现了上面那种用法，文章中因为他是`wsl`链接配置，故没问题，但用`win`下的`sage`时，需要修改文中所提到后缀`*.sage`，只要不是以`.sage`结尾即可，不然会报如下错误，系统将`.sage`识别为`.sage.py`，但实际并不存在该文件；

```
FileNotFoundError: [Errno 2] No such file or directory: '/home/sage/d:\\ctf\\1.sage.py'
```

通过这种方法相当于每一次执行都重启一遍`sagemath`，刚开始会有些等待时间；

1. 首先下载`code runner`插件

2. 点击上方的搜索按键，输入`setting`，找到`setting.json`文件，需要注意目录是`C:>Users>xxx>AppData>Roaming`的文件，本机是在这个默认路径下，其他机子未测试；不过也可以通过文章中提到一般，从设置中步入

3. 进入`setting.json`，找到`code-runner.executorMap`项，将`python`项设为`null`，（注意`setting.json`文件对格式非常严格，在每个键值对末尾都必须都逗号，最后一个可以不要，如果格式有问题，那么在设置里对文件进行修改是无法执行的，同时设定的参数也无法生效）；

   ```
   "code-runner.executorMap": {
           "php": "php",
           "python": null
       },
   ```

4. 找到`code-runner.executorMapByFileExtension`项，修改成如下格式，`.sa`可以自定义名称，但不能改成`.sage`，不然得报错，路径记得替换成自己电脑路径，同时路径前面必须有`\`，`bash.exe`后面必须有`\`，同时单双引号闭合也必须一致，不然就无法使用。

   ```
   "code-runner.executorMapByFileExtension": {
           ".sa": "cd $dir && \"D:\\scoop\\apps\\sagemath\\current\\runtime\\bin\\bash.exe\" --login -c '/opt/sagemath-9.3/sage $fullFileName'",
           ".py": "python",
       },
   ```

## 