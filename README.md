## 一、项目需求
在Linux中实现一个虚拟设备接口模块(VNI), 在IP模块和以太网接口之间串接一个虚拟的vni0接口

# (1)分组格式
· 以太帧头部(14字节):   
目的MAC地址(6字节) = 广播MAC地址  
源MAC地址(6字节) = 发送方的eth0 MAC地址  
类型 = 0xf4f0(即VNI的协议编号)  
· VNI头部(6字节): 4字节学号(最后四个数字) + 2字节分组序  

# (2)VNI功能
· 发送分组  
将Linux内核IP模块送下来的IP分组封装一个VNI头部和一个以太帧头部，然后发给以太接口eth0  
· 接收分组  
将eth0口收到的VNI分组的VNI头部去掉，然后将IP分组上交给Linux内核的IP模块  
· 统计打印  
Ping100个报文，统计VNI模块发送和接收分组的个数，每分钟定时打印以下信息:  
发送端:  
- 当前的发送分组总数  
- 每分钟内的发送速率(pps: 即每秒的发送分组个数)  
接收端:  
- 当前的接收分组总数  
- 每分钟内的接收速率(pps: 即每秒的接收分组个数)  

## 二、项目设计
1. 利用注册虚拟网络设备完成发送分组的VNI功能  
2. 利用注册协议模块完成接收分组的VNI功能  
3. 使用netlink技术完成统计打印，可以写进日志  
4. 编写脚本完成测试  

## 三、项目计划
1. 确立系统架构、技术栈与学习路线  
2. 环境搭建  
3. 内核模块编写学习  
=>内核源码:https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/  
4. 学习注册虚拟网络设备  
5. 学习注册协议模块  
6. netlink复习&编写  
7. 脚本编写&测试  
8. 撰写实验报告  

## 四、项目进度
11.1 借阅书籍《Linux网络编程》，学习了netfilter的相关知识  
11.6 重新规划学习路线  
11.27 选择单队列
11.28 发送时一个注册设备, 接收是一个内核模块；学习网络设备的注册与注销，打开&关闭
11.29 接收端的编写完成
11.30 接收端测试, 看一下网络字节序
12.1 发送端编写, 测试指定虚拟设备发送时，vni_tx获得skb时,其指针指向eth
12.4 发送端的编写测试
12.6 定时器编写并测试
TODO 

## 五、编译说明&常用命令
加载内核模块: sudo insmod vni.ko  
打印内核消息: sudo dmesg [-C #清除内核消息记录]  
卸载内核模块: sudo rmmod vni  
测试传输: scp ~/school/netwoke_commnication/vitrual-internet-device-interface/vni.c zcj@192.168.148.128:~/school/net/vni/test
查询linux内核版本: uname -a
查询路由表: route -n

## 六、 学习笔记
1. 应该使用alloc_netdev还是alloc_netdev_mqs  
选择`alloc_netdev()`还是`alloc_netdev_mqs()`取决于你的需求¹²。

- `alloc_netdev()`函数用于分配网络设备结构，并为驱动程序私有数据预留额外的空间¹。这个函数适用于单队列网络设备¹。

- `alloc_netdev_mqs()`函数也用于分配网络设备结构，并为驱动程序私有数据预留额外的空间¹。但是，这个函数还会为设备上的每个队列分配子队列结构²。这个函数适用于多队列网络设备²。

如果你的设备只有一个队列，那么你可以使用`alloc_netdev()`。如果你的设备有多个队列，那么你应该使用`alloc_netdev_mqs()`²。无论你选择哪个函数，都需要在设备不再使用时通过调用`free_netdev()`函数来释放分配的内存¹。如果单独分配的数据附加到网络设备（`netdev_priv()`），那么释放这些数据的责任就落在模块退出处理程序上¹。在调用`register_netdev()`后，设备在系统中是可见的。用户可以立即打开它并开始发送/接收流量，或者运行任何其他回调，因此所有初始化必须在注册之前完成¹。`unregister_netdev()`关闭设备并等待所有用户完成对它的使用。`struct net_device`本身的内存可能仍然被sysfs引用，但是对该设备的所有操作都将失败。在`unregister_netdev()`返回后或者`register_netdev()`失败时，可以调用`free_netdev()`¹。

源: 与必应的对话， 2023/11/27
(1) Network Devices, the Kernel, and You!. https://www.kernel.org/doc/html/latest/networking/netdevices.html.
(2) HOWTO for multiqueue network device support — The Linux Kernel .... https://www.kernel.org/doc/html/latest/networking/multiqueue.html.
(3) linux内核数据包转发流程：网络设备驱动 - 知乎. https://zhuanlan.zhihu.com/p/344620274.

2. 如何理解单队列和多队列网络设备  
单队列和多队列网络设备的主要区别在于它们处理网络流量的方式¹²³⁴。

- **单队列网络设备**：在这种设备中，所有的网络流量都被放在同一个队列中进行处理³。这意味着，一次只有一个CPU处理每个网络接口的流量¹。这种框架适应的是老式机械盘²。然而，当网络流量增加时，单个CPU可能无法处理所有的流量，这可能会导致性能瓶颈⁴。

- **多队列网络设备**：在这种设备中，网络流量被分配到多个队列中进行处理¹³。这意味着，可以使用多个CPU进行加速¹。多队列网络设备已经是当前高速率网卡的主流¹。多队列网卡是一种技术，最初是用来解决网络IO QoS（quality of service）问题的，后来随着网络IO的带宽的不断提升，单核CPU不能完全满足网卡的需求，通过多队列网卡驱动的支持，将各个队列通过中断绑定到不同的核上，以满足网卡的需求¹。这种框架适应追求更高IOPS的SSD等新设备²。

总的来说，选择单队列还是多队列网络设备取决于你的具体需求和设备的能力¹²³⁴。如果你的设备只有一个队列，那么你可以使用单队列网络设备。如果你的设备有多个队列，那么你应该使用多队列网络设备¹²³⁴。

源: 与必应的对话， 2023/11/27
(1) 网卡多队列：RPS、RFS、RSS、Flow Director（DPDK支持）-CSDN博客. https://blog.csdn.net/Rong_Toa/article/details/108987658.
(2) io 单队列和多队列理解_未央君x的博客-CSDN博客. https://blog.csdn.net/wu7244582/article/details/123003310.
(3) 【精选】什么是队列？（中）_多队列_木可木可 的博客-CSDN博客. https://blog.csdn.net/weixin_44260459/article/details/120971660.
(4) Linux多队列与PCIe SSD（2）. http://www.ssdfans.com/?p=3371.
(5) undefined. http://blog.chinaunix.net/uid-20788636-id-4838269.html.

3. 网络设备注册
设备注册: alloc_netdev(), 其中含有初始化函数来完成设备初始化  
初始化函数核心:见Linux设备驱动程序第三版  
注册与初始化完成后调用: register_netdev()  
当一个驱动需要存取私有数据指针, 应当使用 netdev_priv函数. 

4. 网络设备卸载
从系统中去除接口: unregister_netdev()  
归还net_device结构给内核: free_netdev()  

5. 设备方法
Linux设备驱动程序第三版中介绍的方法太老了，应该改为如下:
本项目使用的内核6.2版本的struct net_device如下: 
https://elixir.bootlin.com/linux/v6.2/source/include/linux/netdevice.h#L126

6. 打开与关闭
open: 
拷贝硬件地址到dev->dev_addr  
启动接口的发送队列

close:
翻转open的操作

7. 接收端相关函数
**
 *	dev_add_pack - add packet handler
 *	@pt: packet type declaration
 *
 *	Add a protocol handler to the networking stack. The passed &packet_type
 *	is linked into kernel lists and may not be freed until it has been
 *	removed from the kernel lists.
 *
 *	This call does not sleep therefore it can not
 *	guarantee all CPU's that are in middle of receiving packets
 *	will see the new packet type (until the next received packet).
 */
void dev_add_pack(struct packet_type *pt);

/**
 *	dev_remove_pack	 - remove packet handler
 *	@pt: packet type declaration
 *
 *	Remove a protocol handler that was previously added to the kernel
 *	protocol handlers by dev_add_pack(). The passed &packet_type is removed
 *	from the kernel lists and can be freed or reused once this function
 *	returns.
 *
 *	This call sleeps to guarantee that no CPU is looking at the packet
 *	type after return.
 */
void dev_remove_pack(struct packet_type *pt);

struct packet_type {
	__be16			type;	/* This is really htons(ether_type). */
	bool			ignore_outgoing;
	struct net_device	*dev;	/* NULL is wildcarded here	     */
	netdevice_tracker	dev_tracker;
	int			(*func) (struct sk_buff *,
					 struct net_device *,
					 struct packet_type *,
					 struct net_device *);
	void			(*list_func) (struct list_head *,
					      struct packet_type *,
					      struct net_device *);
	bool			(*id_match)(struct packet_type *ptype,
					    struct sock *sk);
	struct net		*af_packet_net;
	void			*af_packet_priv;
	struct list_head	list;
};

C语言中的__read_mostly 是什么意思: 
在C语言中，`__read_mostly`是一个用于优化缓存性能的机制。它通过将大部分只读数据放在一起，以减少缓存行的反弹，从而提高缓存的命中率²。在Linux内核代码中，可以通过使用`__read_mostly`修饰符来标记这些只读数据²。

`__read_mostly`原语将定义为存放在`.data.read_mostly`段中。我们可以将经常需要被读取的数据定义为 `__read_mostly`类型，这样Linux内核被加载时，该数据将自动被存放到Cache中，以提高整个系统的执行效率²。另一方面，如果所在的平台没有Cache，或者虽然有Cache，但并不提供存放数据的接口 (也就是并不允许人工放置数据在Cache中)，这样定义为 `__read_mostly`类型的数据将不能存放在Linux内核中，甚至也不能够被加载到系统内存去执行，将造成Linux 内核启动失败²。解决的方法有两种: 修改`include/asm/cache.h`中的`__ready_mostly`定义为：`#define __read_mostly` 或者修改`arch/xxx/kernel/vmlinux.S`，将`.data.read_mostly`段的位置到实际内存空间中去，例如放置在 `.data`段之后等等²。此外，内核源码通过`CONFIG_X86`和 `CONFIG_SPARC64`来判断该怎样定义`__read_mostly`，因此在arm中这个宏没有意义²。

源: 与必应的对话， 2023/11/29
(1) linux内核中的__read_mostly变量-CSDN博客. https://blog.csdn.net/ce123_zhouwei/article/details/8431995.
(2) c - good explanation of __read_mostly, __init, __exit macros - Stack .... https://stackoverflow.com/questions/11505681/good-explanation-of-read-mostly-init-exit-macros.
(3) C Library Functions - GeeksforGeeks. https://www.geeksforgeeks.org/c-library-functions/.

8. skbuff.h相关的结构与函数
struct sk_buff - socket buffer
@dev: Device we arrived on/are leaving by
@protocol: Packet protocol from driver

/**
 *	skb_pull - remove data from the start of a buffer
 *	@skb: buffer to use
 *	@len: amount of data to remove
 *
 *	This function removes data from the start of a buffer, returning
 *	the memory to the headroom. A pointer to the next data in the buffer
 *	is returned. Once the data has been pulled future pushes will overwrite
 *	the old data.
 */
 void *skb_pull(struct sk_buff *skb, unsigned int len)；


 /**
 *	netif_rx	-	post buffer to the network code
 *	@skb: buffer to post
 *
 *	This function receives a packet from a device driver and queues it for
 *	the upper (protocol) levels to process via the backlog NAPI device. It
 *	always succeeds. The buffer may be dropped during processing for
 *	congestion control or by the protocol layers.
 *	The network buffer is passed via the backlog NAPI device. Modern NIC
 *	driver should use NAPI and GRO.
 *	This function can used from interrupt and from process context. The
 *	caller from process context must not disable interrupts before invoking
 *	this function.
 *
 *	return values:
 *	NET_RX_SUCCESS	(no congestion)
 *	NET_RX_DROP     (packet was dropped)
 *
 */
int netif_rx(struct sk_buff *skb)

9. 网络字节序
大端字节序（Big Endian）：最高有效位存于最低内存地址处；
小端字节序（Little Endian）：最低有效位存于最低内存处。
网络字节序是大端字节序
UDP/TCP/IP协议规定：把接收到的第一个字节当作高位字节看待

10. 在内核空间打印MAC地址，使用%pM

11. 发送端相关函数
dev_queue_xmit();

12. 设备信息获取函数
/**
 *	dev_get_by_name		- find a device by its name
 *	@net: the applicable net namespace
 *	@name: name to find
 *
 *	Find an interface by name. This can be called from any
 *	context and does its own locking. The returned handle has
 *	the usage count incremented and the caller must use dev_put() to
 *	release it when it is no longer needed. %NULL is returned if no
 *	matching device is found.
 */

struct net_device *dev_get_by_name(struct net *net, const char *name);

13. 有关skb的headroom区
查看sk_buff头部的剩余空间大小
/**
 *	skb_headroom - bytes at buffer head
 *	@skb: buffer to check
 *
 *	Return the number of bytes of free space at the head of an &sk_buff.
 */
static inline unsigned int skb_headroom(const struct sk_buff *skb)

创建skb的私有副本，带有可写的头和一些头空间
/* Make private copy of skb with writable head and some headroom */
struct sk_buff *skb_realloc_headroom(struct sk_buff *skb, unsigned int headroom)

/**
 *	kfree_skb - free an sk_buff with 'NOT_SPECIFIED' reason
 *	@skb: buffer to free
 */
static inline void kfree_skb(struct sk_buff *skb)

14. 定时器相关
/**
 * timer_setup - prepare a timer for first use
 * @timer: the timer in question
 * @callback: the function to call when timer expires
 * @flags: any TIMER_* flags
 *
 * Regular timer initialization should use either DEFINE_TIMER() above,
 * or timer_setup(). For timers on the stack, timer_setup_on_stack() must
 * be used and must be balanced with a call to destroy_timer_on_stack().
 */
#define timer_setup(timer, callback, flags)

/**
 * mod_timer - Modify a timer's timeout
 * @timer:	The timer to be modified
 * @expires:	New absolute timeout in jiffies
 *
 * mod_timer(timer, expires) is equivalent to:
 *
 *     del_timer(timer); timer->expires = expires; add_timer(timer);
 *
 * mod_timer() is more efficient than the above open coded sequence. In
 * case that the timer is inactive, the del_timer() part is a NOP. The
 * timer is in any case activated with the new expiry time @expires.
 *
 * Note that if there are multiple unserialized concurrent users of the
 * same timer, then mod_timer() is the only safe way to modify the timeout,
 * since add_timer() cannot modify an already running timer.
 *
 * If @timer->function == NULL then the start operation is silently
 * discarded. In this case the return value is 0 and meaningless.
 *
 * Return:
 * * %0 - The timer was inactive and started or was in shutdown
 *	  state and the operation was discarded
 * * %1 - The timer was active and requeued to expire at @expires or
 *	  the timer was active and not modified because @expires did
 *	  not change the effective expiry time
 */
int mod_timer(struct timer_list *timer, unsigned long expires)

/**
 * del_timer - Delete a pending timer
 * @timer:	The timer to be deleted
 *
 * See timer_delete() for detailed explanation.
 *
 * Do not use in new code. Use timer_delete() instead.
 */
static inline int del_timer(struct timer_list *timer)

15. 有关jiffies
在Linux系统中，jiffies是一个全局变量，用于记录自系统启动以来产生的时钟中断次数。要将jiffies设置为1分钟，您需要根据系统的时钟频率（HZ）来计算。HZ值表示系统每秒中断的次数。例如，如果HZ值为100，则表示每秒有100次中断，那么1分钟（60秒）的jiffies值将是60 * HZ。