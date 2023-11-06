#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>

MODULE_LICENSE("GPL");

struct net_device *vni_dev;

static int __init vni_init(void)
{
    // vni_dev = alloc_netdev(sizeof(struct ))
    printk(KERN_ALERT "vni_init\n");
    return 0;
}

static void __exit vni_exit(void)
{
    printk(KERN_ALERT "vni_exit\n");
}

module_init(vni_init);
module_exit(vni_exit);