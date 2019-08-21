/*
 * This module simply copies the skb->markt to the skb->priority field
 * of an skb for qdisc classification.
 */

/* Copyright (c) 2013, The Linux Foundation. All rights reserved.
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

MODULE_AUTHOR("Rob <github.com/robcore>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: Straight up Prio Hack");

static unsigned int
mark2prio_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	skb->priority = skb->mark;

	return NF_ACCEPT;
}

static struct xt_target mark2prio_tg_reg[] __read_mostly = {
	{
		.name		= "mark2prio",
		.revision   = 0,
		.family		= NFPROTO_UNSPEC,
		.target		= mark2prio_tg,
		.targetsize	= 0,
		.hooks		= (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_IN) |
					  (1 << NF_INET_FORWARD) | (1 << NF_INET_LOCAL_OUT) |
					  (1 << NF_INET_POST_ROUTING),
		.me         = THIS_MODULE,
	},
};

static int __init mark2prio_tg_init(void)
{
	return xt_register_targets(mark2prio_tg_reg,
				   ARRAY_SIZE(mark2prio_tg_reg));
}

static void __exit mark2prio_tg_exit(void)
{
	xt_unregister_targets(mark2prio_tg_reg, ARRAY_SIZE(mark2prio_tg_reg));
}

module_init(mark2prio_tg_init);
module_exit(mark2prio_tg_exit);
