/**
 * xt_sip - match SIP packets.
 * Copyright (C) 2013 Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "xt_sip.h"

#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/netfilter/nf_conntrack_helper.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: match sip packets");
MODULE_ALIAS("ipt_sip");
MODULE_ALIAS("ip6t_sip");

static struct nf_conntrack_helper *sip_helper;

static bool sip_request(const struct sk_buff *skb, unsigned int doff)
{
	char buf[sizeof("SIP/2.0")];
	struct skb_seq_state st;
	const u8 *data;
	unsigned int len;
	unsigned int consumed = 0;

	skb_prepare_seq_read((struct sk_buff *)skb, doff, skb->len, &st);
	while ((len = skb_seq_read(consumed, &data, &st)) != 0) {
		while (len-- > 0) {
			switch (*data++) {
			case '\r':
			case '\n':
				break;
			default:
				consumed++;
				continue;
			}
			skb_abort_seq_read(&st);
			if (consumed < sizeof(buf))
				goto err;
			skb_copy_bits(skb, doff + consumed - sizeof(buf) + 1,
					buf, sizeof(buf) - 1);
			if (strncasecmp(buf, "sip/", 4) != 0)
				goto err;
			return true;
		}
	}
err:
	return false;
}

static int sip_assign_helper(struct nf_conn *ct, u16 l3num, u8 protonum)
{
	struct nf_conntrack_helper *helper;
	int retval;
	struct nf_conn_help *help;

	helper = __nf_conntrack_helper_find("sip", l3num, protonum);
	if (!helper) {
		retval = -ENOENT;
		goto err;
	}

	help = nfct_help(ct);
	if (help) {
		retval = -EEXIST;
		goto err;
	}
	help = nf_ct_helper_ext_add(ct, helper, GFP_ATOMIC);
	if (!help) {
		retval = -ENOMEM;
		goto err;
	}

	rcu_assign_pointer(help->helper, helper);
	retval = 0;
err:
	return retval;
}

static bool sip_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_sip_info *info = par->matchinfo;
	struct nf_conn *ct;
	const struct nf_conn_help *help;
	const struct nf_conntrack_helper *helper;
	enum ip_conntrack_info ctinfo;
	u8 flags;
	u8 proto;
	unsigned int doff;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		goto err;
	help = nfct_help(ct);
	if (help && (helper = rcu_dereference(help->helper))) {
		if (strncmp(helper->name, "sip", 3) != 0)
			goto err;
		flags = XT_F_SIP_SIGNAL;
		goto out;
	}

	if (ct->master && (help = nfct_help(ct->master)) &&
	    (helper = rcu_dereference(help->helper))) {
		u16 odport;

		if (strncmp(helper->name, "sip", 3) != 0)
			goto err;
		odport = ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);
		if (odport & 1)
			flags = XT_F_SIP_RTCP;
		else
			flags = XT_F_SIP_RTP;
		goto out;
	}

	/**
	 * The helper ext only can be added to unconfirmed connections.
	 * It also implies that application data based helper assigning only
	 * works for UDP connections.
	 */
	if (nf_ct_is_confirmed(ct))
		goto err;
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		goto err;

	/* Get l4 protocol */
	if (par->family == NFPROTO_IPV4) {
		if (skb_copy_bits(skb, offsetof(struct iphdr, protocol),
					&proto, sizeof(proto)))
			goto err;
	} else if (par->family == NFPROTO_IPV6) {
		int protoff;
		__be16 frag_off;

		if (skb_copy_bits(skb, offsetof(struct ipv6hdr, nexthdr),
					&proto, sizeof(proto)))
			goto err;
		protoff = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr),
				&proto, &frag_off);
		if (protoff < 0 || (frag_off & htons(~0x7)) != 0)
			goto err;
	} else {
		goto err;
	}

	/* Get the offset of data */
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcph, _tcph;

		tcph = skb_header_pointer(skb, par->thoff, sizeof(_tcph),
				&_tcph);
		if (!tcph)
			goto err;
		doff = tcph->doff * 4;
	} else if (proto == IPPROTO_UDP) {
		doff = sizeof(struct udphdr);
	} else {
		goto err;
	}
	doff += par->thoff;

	if (doff >= skb->len)
		goto err;
	if (!sip_request(skb, doff))
		goto err;
	if (sip_assign_helper(ct, nf_ct_l3num(ct), nf_ct_protonum(ct)))
		goto err;
	flags = XT_F_SIP_SIGNAL;
out:
	return !!(info->flags & flags);
err:
	return false;
}

static int sip_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_sip_info *info = par->matchinfo;

	if (info->flags == 0 || info->flags & ~XT_F_SIP_ANY)
		return -EINVAL;

	return nf_ct_l3proto_try_module_get(par->family);
}

static void sip_mt_destroy(const struct xt_mtdtor_param *par)
{
	nf_ct_l3proto_module_put(par->family);
}

static struct xt_match sip_mt_reg __read_mostly = {
	.name		= "sip",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.checkentry	= sip_mt_check,
	.destroy	= sip_mt_destroy,
	.match		= sip_mt,
	.matchsize	= sizeof(struct xt_sip_info),
	.me		= THIS_MODULE,
};

static int __init sip_mt_init(void)
{
	int retval;

	sip_helper = nf_conntrack_helper_try_module_get("sip", AF_INET,
			IPPROTO_UDP);
	if (!sip_helper) {
		pr_err("sip helper is needed\n");
		return -ENOENT;
	}

	retval = xt_register_match(&sip_mt_reg);
	if (retval)
		module_put(sip_helper->me);

	return retval;
}

static void __exit sip_mt_exit(void)
{
	xt_unregister_match(&sip_mt_reg);
	module_put(sip_helper->me);
}

module_init(sip_mt_init);
module_exit(sip_mt_exit);
