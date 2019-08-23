/*
 * This is a module which is used for setting the skb->priority field
 * directly and accepting the packet immediately.
 */

/* (C) 2019 Rob Patershuk <robpatershuk@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_PRIO.h>
#include <linux/netfilter_arp.h>

MODULE_AUTHOR("Rob Patershuk <robpatershuk@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: Set SKB Priority and Accept Packet");
MODULE_ALIAS("ipt_PRIO");
MODULE_ALIAS("ip6t_PRIO");

static unsigned int
prio_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_prio_target_info *prinfo = par->targinfo;

	skb->priority = prinfo->priority;
	return NF_ACCEPT;
}

static struct xt_target prio_tg_reg[] __read_mostly = {
	{
		.name       = "PRIO",
		.revision   = 0,
		.family     = NFPROTO_UNSPEC,
		.hooks      = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_PRE_ROUTING) |
					  (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_FORWARD) |
		              (1 << NF_INET_POST_ROUTING),
		.target     = prio_tg,
		.targetsize = sizeof(struct xt_prio_target_info),
		.me         = THIS_MODULE,
	},
};

static int __init prio_tg_init(void)
{
	return xt_register_targets(prio_tg_reg, ARRAY_SIZE(prio_tg_reg));
}

static void __exit prio_tg_exit(void)
{
	xt_unregister_targets(prio_tg_reg, ARRAY_SIZE(prio_tg_reg));
}

module_init(prio_tg_init);
module_exit(prio_tg_exit);
