#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");

#define VNI_PROTO 0xf4f0

void vni_setup(struct net_device* dev);
int vni_open(struct net_device *dev);
int vni_release(struct net_device *dev);
netdev_tx_t	vni_tx(struct sk_buff *skb,struct net_device *dev);
int vni_rx(struct sk_buff *skb, struct net_device *dev,struct packet_type *ptype, struct net_device *orig_dev);
void vni_timer_callback(struct timer_list *timer);

struct net_device *vni_dev;
struct net_device_ops vni_dev_ops;
static struct timer_list vni_timer;

// 发送端私有网络设备的私有属性
struct vni_priv 
{
    unsigned int rx_packets;    // 接收端流量统计
    unsigned int tx_packets;    // 发送端流量统计
    __u16 sequence;             // 报文序列号
};


// 设置接收到私有报文时触发的处理函数
static struct packet_type vni_packet_type __read_mostly = {
.type = cpu_to_be16(VNI_PROTO),
.func = vni_rx,
};

// 私有协议头
struct vni_hdr
{
	unsigned  char  number1;
	unsigned  char  number2;
	unsigned  char  number3;
	unsigned  char  number4;
	__u16 sequence;
}__attribute__((packed));  // __attrubte__ ((packed)) 的作用就是告诉编译器取消结构在编译过程中的优化对齐,按照实际占用字节数进行对齐。

// 发送端私有网络设备操作
struct net_device_ops vni_dev_ops = {
// 基本方法
.ndo_open = vni_open,
.ndo_stop = vni_release,
.ndo_start_xmit = vni_tx,
};

// 定时器到期回调函数
void vni_timer_callback(struct timer_list *timer)
{
    
    struct vni_priv *priv;
    priv = netdev_priv(vni_dev);
    printk(KERN_INFO "timer expire rx_packets: %u tx_packets: %u\n", priv->rx_packets, priv->tx_packets);
    mod_timer(&vni_timer, jiffies + 60 * HZ);
}

// 发送端私有网络设备初始化函数
void vni_setup(struct net_device* dev)
{
    ether_setup(dev);
    dev->netdev_ops = &vni_dev_ops;
    dev->flags |= IFF_NOARP;
    return;
}

int vni_open(struct net_device *dev)
{
    // 设置成ens33相同mac
    unsigned char ethSrc[ETH_ALEN] = {0x00, 0x0c, 0x29, 0xf5, 0x74, 0x5e};
    // unsigned char ethSrc[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x99, 0x41, 0x8a};
    printk(KERN_INFO "vni open\n");
    memcpy(dev->dev_addr, ethSrc, ETH_ALEN);

    netif_start_queue(dev);  // Allow upper layers to call the device hard_start_xmit routine.
    return 0;
}

int vni_release(struct net_device *dev)
{
    // 退出时可能得再保存一次统计数据
    struct vni_priv *priv;
    priv = netdev_priv(vni_dev);
    printk(KERN_INFO "rx_packets: %u tx_packets: %u\n", priv->rx_packets, priv->tx_packets);

    del_timer(&vni_timer);
    printk(KERN_INFO "timer close\n");

    netif_stop_queue(dev);  // Stop upper layers calling the device hard_start_xmit routine.
    printk(KERN_INFO "vni close\n");
    return 0;
}

// 获得IP报文， 封装私有链路头部和以太帧头部， 最终发给ens33物理网卡进行转发处理
netdev_tx_t	vni_tx(struct sk_buff *skb,struct net_device *dev)
{
    // 获取虚拟设备相关信息
    struct vni_priv *priv;
    priv = netdev_priv(vni_dev);
    // 获取ens33的设备信息，使用ens33的地址作为物理地址
    struct net_device* ens_dev;
	ens_dev = dev_get_by_name(&init_net, "ens33");
    // 私有链路协议帧头部没有type字段，要求只能对IP进行处理，因此在设置以太网头部的时候目的地址直接设置成指定的
    // unsigned char ethDest[ETH_ALEN] = {0x00, 0x0c, 0x29, 0xf5, 0x74, 0x5e};
    unsigned char ethDest[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x99, 0x41, 0x8a};
    // 打印ip头部便于调试
    // struct iphdr *ihdr;
    // ihdr = ip_hdr(skb);
    // printk(KERN_INFO "vni_tx: ihdr->saddr: %d ihdr->saddr: %d", ihdr->saddr, ihdr->daddr);
    // 为skb分配带有headroom的头部空间
    struct sk_buff *skb2;
	if (skb_headroom(skb) < (sizeof(struct vni_hdr))) {
		printk(KERN_INFO "vni_tx realloc_headroom\n");
		skb2 = skb_realloc_headroom(skb, (sizeof(struct vni_hdr)));
		if (!skb2) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		// if (skb->sk)
		// 	skb_set_owner_w(skb2, skb->sk);
		consume_skb(skb);
		skb = skb2;
	}

    // 此时skb的ethhdr相关信息已经存在, skb的指针指向ethhdr
    struct ethhdr* ehdr;
    ehdr = (struct ethhdr*)skb;
    skb_pull(skb, sizeof(struct ethhdr));
    // 封装虚拟头部
    struct vni_hdr *vhdr;
    vhdr = skb_push(skb, sizeof(struct vni_hdr));
    vhdr->number1 = 1;
    vhdr->number2 = 0;
    vhdr->number3 = 0;
    vhdr->number4 = 8;
    vhdr->sequence = htons(priv->sequence++);
    // 重新封装以太帧头部, 源地址是ens33,目的地址是对端的ens33
    ehdr = skb_push(skb, sizeof(struct ethhdr));
    memcpy(ehdr->h_source, ens_dev->dev_addr, ETH_ALEN);
    memcpy(ehdr->h_dest, ethDest, ETH_ALEN);
    ehdr->h_proto = htons(VNI_PROTO);
    printk(KERN_INFO "vni_tx ehdr->h_source: %pM ehdr->h_dest: %pM ehdr->h_proto: 0x%x\n", ehdr->h_source, ehdr->h_dest, ntohs(ehdr->h_proto));
    // 指定ens33为skb的发送设备
    skb->dev = ens_dev;
	dev_queue_xmit(skb);
    // 发送端统计流量
    priv->tx_packets++;
    return NETDEV_TX_OK;
}

int vni_rx(struct sk_buff *skb, struct net_device *dev,struct packet_type *ptype, struct net_device *orig_dev)
{
    struct vni_hdr *vhdr;
    struct vni_priv *priv;

    // 此时skb的指针应该指向的是pri头部，为了便于调试, 获得skb的eth头部来获得的mac信息
    struct ethhdr* eth;
    eth = eth_hdr(skb);
    printk(KERN_INFO "vni_rx eth->h_source: %pM eth->h_dest: %pM\n", eth->h_source, eth->h_dest);

    vhdr = (struct vni_hdr *)skb->data;
    printk(KERN_INFO "studentId: %u%u%u%u, sequence: %u", vhdr->number1, vhdr->number2, vhdr->number3, vhdr->number4, ntohs(vhdr->sequence));

    // 去掉私有协议头（私有链路协议本身不提供上层协议类型type字段，需要重新设置0x800）
    skb_pull(skb, sizeof(struct vni_hdr));
    // 打印ip头部便于调试
    skb_reset_network_header(skb);

    skb->dev = vni_dev;
    skb->protocol = ntohs(0x0800);
    netif_rx(skb);

    // 接收端流量统计
    priv = netdev_priv(vni_dev);
    priv->rx_packets++;
    return 0;
}



static int __init vni_init(void)
{
    vni_dev = alloc_netdev(sizeof(struct vni_priv), "vni%d", NET_NAME_ENUM, vni_setup);
    if(register_netdev(vni_dev) != 0) 
    {
        printk(KERN_INFO "register fail\n");
    }

    // 完成私有网络设备成员的初始化
    struct vni_priv *priv;
    priv = netdev_priv(vni_dev);
    priv->rx_packets = 0;
    priv->tx_packets = 0;
    priv->sequence = 0;

    // 添加私有协议
    dev_add_pack(&vni_packet_type);

    // 设置定时器
    timer_setup(&vni_timer, vni_timer_callback, 0);
    mod_timer(&vni_timer, jiffies + 60 * HZ);

    printk(KERN_INFO  "vni_init\n");
    return 0;
}

static void __exit vni_exit(void)
{
    dev_remove_pack(&vni_packet_type);
    unregister_netdev(vni_dev);
    free_netdev(vni_dev);
    printk(KERN_ALERT "vni_exit\n");
}

module_init(vni_init);
module_exit(vni_exit);