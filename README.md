# Fio for Curve README

curve fio 是从 [axboe/fio](https://github.com/axboe/fio) 仓库 fork 而来，为 fio 新增了 PFS 和 NEBD/CBD 的 ioengine，用于 curve 的性能测试。

## 1. 编译

### 1.1 编译前准备

curve fio 的编译推荐在 debian 操作系统下编译和运行。在编译 curve fio 前，首先需要安装 PFS 和 NEBD/CBD 的 ioengine 所依赖的动态库和头文件。

#### 1.1.1. CBD ioengine 的编译准备
CBD ioengine 的编译依赖 curve sdk 的动态库和头文件。因此，在编译curve fio前，需要先编译和安装 curve sdk。 

curve sdk 支持通过tar包的方式手动安装，参考[链接](https://github.com/opencurve/curve/blob/master/docs/cn/curve%E9%80%9A%E8%BF%87tar%E5%8C%85%E6%89%8B%E5%8A%A8%E9%83%A8%E7%BD%B2sdk.md)。此外也可以通过源码的方式编译和打包，在debian操作系统下执行mk-deb.sh脚本生成 curve sdk 的 deb 安装包，然后进行安装。

如果希望在 centos 7 下操作系统下安装和运行 curve fio。在编译 curve fio 前，首先需要：
1. 升级 GCC 版本要求大于4.9，推荐使用 gcc 7.3.0（经过验证），安装 gcc 7.3.0 版本可以解决后续遇到的 version `GLIBCXX_3.4.21‘ not found 问题。
2. 升级 openssl 到 1.1.1 版本。

#### 1.1.2. NEBD ioengine 的编译准备
TODO

#### 1.1.3. PFS ioengine 的编译准备
TODO

### 1.2 编译fio
执行 ./configure 检查 PFS 和 NEBD/CBD 的 fio ioengine 是否由 no 改为 yes。如果依然是 no，需要重新检查并执行上一步骤。

![image](examples/config-curve.png)

然后执行 make 编译 curve fio。

## 2. 测试curve卷
### 2.1 使用nebd引擎测试curve卷
#### 2.1.1 配置fio

创建配置文件 nebd_global.fio, 包含如下内容
```
ioengine=nebd
nebd=cbd:pool//volpath_owner_  #格式为前缀(cbd:pool/) + 卷路径(/volpath) + _ + 用户(owner) + _
size=10G
bs=16K
direct=1
time_based
```

创建配置文件 nebd_seqw.fio, 该文件用于做顺序写测试，包含如下内容
```
[global]
include nebd_global.fio

[seqwrite]
rw=write
iodepth=1
numjobs=1
runtime=900
```

创建配置文件 nebd_randw.fio，该文件用于做随机写测试，包含如下内容
```
[global]
include nebd_global.fio

[randwrite]
rw=randwrite
iodepth=16
numjobs=10
runtime=900
```

#### 2.1.2 测试

顺序写测试:
sudo ./fio ./nebd_seqw.fio

随机写测试:
sudo ./fio ./nebd_randw.fio

### 2.2 使用cbd引擎测试curve卷
#### 2.2.1 配置fio

创建配置文件 cbd_global.fio, 包含如下内容
```
ioengine=cbd
cbd=/volpath_owner_  #格式为卷路径(/volpath) + _ + 用户(owner) + _
size=10G
bs=16K
direct=1
time_based
```

创建配置文件 cbd_seqw.fio, 该文件用于做顺序写测试，包含如下内容
```
[global]
include cbd_global.fio

[seqwrite]
rw=write
iodepth=1
numjobs=1
runtime=900
```

创建配置文件 cbd_randw.fio，该文件用于做随机写测试，包含如下内容
```
[global]
include  cbd_global.fio

[randwrite]
rw=randwrite
iodepth=16
numjobs=10
runtime=900
```

#### 2.2.2 测试

顺序写测试:
sudo ./fio ./cbd_seqw.fio

随机写测试:
sudo ./fio ./cbd_randw.fio

## 3. 测试pfs
### 3.1 启动pfs守护进程

假设你有一个curvebs卷名cbd:pool//pfs_test_, 启动pfs守护进程如下:

```
sudo /usr/local/polarstore/pfsd/bin/start_pfsd.sh -p pool@@pfs_test_
```
注意pfs使用curvebs卷名的方式是: 'cbd:'前缀是不要的，'//'要需要转换成'@@''

创建pfs文件系统:
```
sudo pfs -C curve -H 1 mkfs pool@@pfs_test_
```

### 3.2 配置fio
创建配置文件 pfs_global.fio
```
ioengine=pfs
cluster=curve
pbd=pool@@pfs_test_
filename=/pool@@pfs_test_/fio-write #格式为/ + pbdname(pool@@pfs_test_) + 测试文件路径(/fio-write), 其中pbdname格式为前缀(pool@@) + 卷名(pfs) + _ + 用户名(test) + _
size=10G
bs=16K
direct=1
time_based
```

创建配置文件 pfs_seqw.fio，该文件用于做顺序写测试，包含如下内容
```
[global]
include pfs_global.fio

[seqwrite]
runtime=900
rw=write
iodepth=1
numjobs=1
```

创建配置文件 pfs_randw.fio，该文件用于做随机写测试，包含如下内容
```
[global]
include pfs_global.fio

[randwrite]
rw=randwrite
iodepth=16
numjobs=10
runtime=900
```
### 3.3 测试

顺序写测试:
sudo ./fio ./pfs_seqw.fio

随机写测试:
sudo ./fio ./pfs_randw.fio
