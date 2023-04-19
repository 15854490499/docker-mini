

Simple Docker
===============
Linux下对于docker容器的简单模拟

* [原作地址](https://www.lanqiao.cn/courses/608)

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

* 启动

    ```C++
    ./docker-run
    ```

