#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x122c3a7e, "_printk" },
	{ 0x15ba50a6, "jiffies" },
	{ 0xc38c83b8, "mod_timer" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xa9b76a70, "ether_setup" },
	{ 0xdc0e4855, "timer_delete" },
	{ 0xb4d34ef6, "skb_pull" },
	{ 0xa4ac7763, "netif_rx" },
	{ 0x8f93170d, "alloc_netdev_mqs" },
	{ 0x99fb7e01, "register_netdev" },
	{ 0x3022a95d, "dev_add_pack" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x6ff24b3a, "dev_remove_pack" },
	{ 0x38c7ddda, "unregister_netdev" },
	{ 0x240f1dee, "free_netdev" },
	{ 0xa19b956, "__stack_chk_fail" },
	{ 0x316f68bc, "init_net" },
	{ 0x83d29be5, "dev_get_by_name" },
	{ 0x1a35fca5, "skb_realloc_headroom" },
	{ 0x4bb2c6c0, "consume_skb" },
	{ 0xc26fbe0c, "skb_push" },
	{ 0xdc228b17, "__dev_queue_xmit" },
	{ 0x22cc9093, "kfree_skb_reason" },
	{ 0x453e7dc, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "4B24A9548487D863EEBBD35");
