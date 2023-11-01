一、项目需求
在Linux中实现一个虚拟设备接口模块(VNI), 在IP模块和以太网接口之间串接一个虚拟的vni0接口

(1)分组格式
· 以太帧头部(14字节): 
目的MAC地址(6字节) = 广播MAC地址
源MAC地址(6字节) = 发送方的eth0 MAC地址
类型 = 0xf4f0(即VNI的协议编号)
· VNI头部(6字节): 4字节学号 + 2字节分组序

(2)VNI功能
· 发送分组
将Linux内核IP模块送下来的IP分组封装一个VNI头部和一个以太帧头部，然后发给以太接口eth0
· 接收分组
讲eth0口收到的VNI分组的VNI头部去掉，然后将IP分组上交给Linux内核的IP模块
· 统计打印
Ping100个报文，统计VNI模块发送和接收分组的个数，每分钟定时打印以下信息:
发送端:
- 当前的发送分组总数
- 每分钟内的发送速率(pps: 即每秒的发送分组个数)
接收端:
- 当前的接收分组总数
- 每分钟内的接收速率(pps: 即每秒的接收分组个数)

二、项目设计
1. 利用netfilter完成发送分组与接收分组的VNI功能
2. 使用netlink技术完成统计打印，可以写进日志
3. 编写脚本完成测试

三、项目计划
1. 确立系统架构、技术栈与学习路线
2. 环境搭建
3. 内核模块编写学习
=>内核源码:https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/
4. netfilter学习&编写
5. netlink复习&编写
6. 脚本编写&测试
7. 撰写实验报告

四、项目进度
11.1 借阅书籍《Linux网络编程》，学习了netfilter的相关知识
TODO 编写netfilter并进行测试

五、编译说明
加载内核模块: sudo insmod xxx.ko
打印内核消息: sudo dmesg [-C #清除内核消息记录]
卸载内核模块: sudo rmmod xxx
