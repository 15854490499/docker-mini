

Simple Docker
===============
Linux下对于docker容器引擎的简单模拟

* [原作地址](https://www.lanqiao.cn/courses/608)
* [参考项目](https://gitee.com/openeuler/iSulad)
* [参考项目](https://gitee.com/calvinwilliams/cocker)

介绍
------------
基于oci镜像规范的模拟容器引擎，支持从docker仓库中拉取镜像，删除镜像，创建容器，运行容器，删除容器等功能。

* 拉取镜像
	oci定义容器镜像为四部分，由mediaType区分各个部分。

	* [清单列表（manifest-list）或者清单索引（oci-index）](https://docs.docker.com/registry/spec/manifest-v2-2/)
	  该部分给出了特定容器镜像的对应平台版本，如arm、x86_64等，拉取容器镜像首先需要拉取这部分，从中获取对应平台镜像的摘要值digest。
	  本项目只实现了amd64平台的镜像拉取。

	* [镜像清单（manifest）](https://docs.docker.com/registry/spec/manifest-v2-2/)
	  该部分给出了镜像的配置文件（config）信息和层（layers）信息，主要包含mediaType、size、digest，有了这些信息就可以拉取对应镜像的配置和层文件。
	
	* 镜像配置（config）
	  该部分描述了容器的根文件系统（rootfs）和容器运行时使用的执行参数，根文件系统中包含了不同layer的diff_id，用于检查拉取layer的完整性以及
	  layer在不同镜像间共享。此时需要计算每个layer的chain_id = sha256sum(parent_chain_id, diff_id)，作为每个layer在宿主机上的目录名。

	* 镜像层（layer）
	  每个镜像的多个层共同组成了该镜像的根文件系统，拉取下来的layer作为tar压缩包存在，里面包含了diff、merged、work等作为overlay文件系统挂载时必须
	  的文件夹。拉取layer后需要将其注册到本地，使用[libarchive库](https://www.libarchive.org/)解压到对应文件夹下diff目录。而后将layer信息保存为json
	  文件。
	
	拉取完镜像后需要将镜像注册到本地。
	1. 先以镜像config的digest作为镜像id创建文件夹。
	2. 在文件夹中创建images.json文件存储镜像信息。
	3. 将config文件内容存入该文件夹下以经过base64加密过的config.digest作为文件名的文件中。
	4. 将manifest文件内容存入该文件夹下以相同方式产生的文件中。
	5. 将config文件和manifest文件作为big-data更新到images.json。
	6. 将镜像保存时间更新到images.json。
	
	镜像注册目录为/var/lib/docker-mini。

快速运行
------------
* 服务器测试环境
	* Ubuntu版本20.04

* 创建网桥并分配ip地址

    ```C++
    // 创建网桥
    brctl addbr docker0

    // 分配ip
    ifconfig docker0 192.168.0.1

    // 打开转发配置
    sysctl net.ipv4.conf.all.forwarding=1
	iptables -P FORWARD ACCEPT

	//使用NAT
	iptables -t nat -A POSTROUTING -s 192.168.0.1/16 ! -o br0 -j MASQUERADE
    ```
* build

    ```C++
    sudo make
    ```

* 拉取镜像

    ```C++
    bin/./docker-mini pull image-name
    ```

* 删除镜像
	
	```C++
    bin/./docker-mini rmi image-name
	```

* 创建容器

	```C++
    bin/./docker-mini create image-name
	```

* 启动容器

	```C++
    bin/./docker-mini start container-id
	```

* 删除容器

	```C++
    bin/./docker-mini rm container-id
	```
