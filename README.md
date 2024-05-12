

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
	oci定义容器镜像为四部分，由mediaType区分各个部分。拉取镜像时，使用yajl库解析json文件，同时利用[libocispec](https://github.com/containers/libocispec)
	自动生成解析和生成json文件的代码。

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

* 删除镜像
	
	1. 删除镜像前需要检查该镜像是否仍被某个容器使用。
	2. 删除在拉取镜像时建立的层文件夹。
	3. 删除镜像文件。

* 创建容器
	
	1. 获取容器底层镜像的id。
	2. 为容器创建overlay文件系统读写层。  

	* 检查宿主机文件系统是否支持quota，目前仅支持xfs和ext4文件系统。用户通过设置quota限制底层rootfs大小防止将磁盘占满。
	* 创建读写层对应diff、work、merged文件夹并注册到/var/lib/docker-mini/overlay-layers文件夹下。
	* 保存层配置。  

	3. 创建容器配置文件并保存。
	4. 检查挂载和卸载容器根文件系统是否有问题。

* 删除容器  
	
	1. 卸载根文件系统。
	2. 删除容器读写层文件夹。
	3. 删除容器配置文件。

* 运行容器
	
	* [overlay2文件系统](https://docs.docker.com/storage/storagedriver/overlayfs-driver)  

	  以nginx:latest镜像为image layers的容器为例，挂载时使用mount系统调用，source参数为"overlay"，target参数为"/var/lib/docker-mini/overlay/<conatiner-id>/merged"，
	  filesystemtype参数为"overlay", data参数为"lowerdir=/var/lib/docker-mini/overlay/l/e5b5dd506285cd715d73152012:  
	  /var/lib/docker-mini/overlay/l/5a07ef8eaecdd048f1357e2e72:  
	  /var/lib/docker-mini/overlay/l/b818003a0c94adbaf467eee4e4:  
	  /var/lib/docker-mini/overlay/l/6631e6653cc25a44d009acc08c:  
	  /var/lib/docker-mini/overlay/l/f2299249489af33a4fce380361:  
	  /var/lib/docker-mini/overlay/l/ab6e6b5bacd8f5060576108e5b:  
	  /var/lib/docker-mini/overlay/l/f191ad573e2d31f5169d0f9006,  
	  upperdir=/var/lib/docker-mini/overlay/\<container-id\>/diff,workdir=/var/lib/docker-mini/overlay/\<container-id\>/work"。
	
	* [网络配置](https://blog.csdn.net/qq_36733838/article/details/127592976)
	  
	1. 新建网桥docker-mini0，为其分配ip地址。使用nat地址转换使得虚拟机内网可以访问外网。
	2. 创建虚拟网卡veth2及其配对veth1，两者通过netlink通信。
	   其中veth1连接到网桥，veth2作为网卡放入运行容器内并将其取名为eth0。
	3. 设置容器网卡ip和子网掩码，启动veth1、veth2，将容器网关地址设为网桥地址。
	4. 设置容器mac地址  

	* clone创建namespace  

	1. CLONE_NEWPID标志位通过置零父子进程间共享pid namespace，使得宿主机操作系统内核为子进程创建新的pid namespace。高级别namespace可以看到低级别namespace的pid，反之不可。
	2. CLONE_NEWNS标志位置零进程间挂载点共享，为容器提供挂载点隔离，每个mount namespace都拥有一份自己的挂载点列表，低级别映射无法影响到高级别挂载点。
	3. CLONE_UTS标志位置零进程间UTS共享，为容器隔离hostname、domainname以及操作系统内核版本等，子进程会复制父进程相关信息直至被更改。
	4. CLONE_NEWNET标志位置零进程间网络资源共享， 如网络设备，协议栈，路由表，防火墙规则，端口等。  

	* cgroups限制cpu、内存资源

	* disk quota限制磁盘资源
		

快速运行
------------
* 服务器测试环境
	* Ubuntu版本20.04

* 创建网桥并分配ip地址

    ```C++
    // 创建网桥
    brctl addbr docker-mini0

    // 分配ip
    ifconfig docker-mini0 192.168.0.1

    // 打开转发配置
    sysctl net.ipv4.conf.all.forwarding=1
	iptables -P FORWARD ACCEPT

	//使用NAT
	iptables -t nat -A POSTROUTING -s 192.168.0.1/16 ! -o docker-mini0 -j MASQUERADE
    ```  

* 创建配置文件

	将位于项目目录下configs文件下constants.json文件复制到/etc/docker-mini/configs文件夹下。

* [编译安装http-parser库](https://github.com/nodejs/http-parser)

	```C++
	make  
	make parsertrace  
	make url_parser  
	make install  
	```

* [编译安装libarchive库](https://www.libarchive.org)

	```C++
	mkdir build && cd build  
	../configure --prefix=/usr CFLAGS='-O2 -v'  
	make && make install
	```

* [compile and install lxc](https://github.com/lxc/lxc.git)

	```C++
	sudo -E meson setup build --default-library=static -Dinit-script=sysvinit -Ddbus=false -Dstrip=true -Dcapabilities=true -Dseccomp=true -Dselinux=false -Dapparmor=false -Dc_link_args="-O2"
	sudo -E ninja -C build && sudo -E ninja -C build install
	```

* [compile and install grpc](https://github.com/grpc/grpc.git)
	

* build

    ```C++
    sudo -E make LXC_PATH=your-lxc-lib-path GRPC_PATH=your-grpc-lib-path
    ```

* 启动服务端

	```C++
    sudo -E bin/./docker-minid
    ```

* 拉取镜像

    ```C++
    sudo -E bin/./docker-mini pull image-name 如（nginx）
    ```

* 删除镜像
	
	```C++
    sudo -E bin/./docker-mini rmi image-name
	```

* 创建容器

	```C++
    sudo -E bin/./docker-mini create image-name
	```

* 启动容器

	```C++
    sudo -E bin/./docker-mini start container-id  
	  

	--memory / -m 添加cgroup memory limit，如-m 10485760  
	  

	--cpu-period / --cpu-quota 添加cgroup cpu cfs调度资源限制，如--cpu-period 100000 --cpu-quota 30000
	```  

	以启动nginx为镜像的容器为例，演示nginx容器启动。  

	1. 在容器内创建必要的设备节点  
	``` C++
	mknod /dev/null c 1 3
	chmod 666 /dev/null
	```  
	2. 修改容器内nginx.conf文件，添加
	```C++
	user  root;
	```
	3. 启动nginx，在宿主机内连接容器nginx，http:192.168.0.100:80，结果如图。  
	![nginx.jpg](https://github.com/15854490499/docker-mini/blob/main/nginx.png) 

* 连接容器

	```C++
    sudo -E bin/./docker-mini attach container-id
	```

* 关闭容器
	
	```C++
    sudo -E bin/./docker-mini stop container-id
	```

* 删除容器

	```C++
    sudo -E bin/./docker-mini rm container-id
	```


后续
------------

* 完善cpu、memory quota。

* 增加查询镜像和容器功能。
 
