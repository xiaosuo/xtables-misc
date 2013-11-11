/**
 * xt_COMPRESS - compress/decompress the UDP payload.
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

#include "xt_COMPRESS.h"

#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: compress/decompress the UDP payload");
MODULE_ALIAS("ipt_COMPRESS");

#define COMPRESS_SCRATCH_SIZE	65536

static void * __percpu *compress_scratches;

static int append_data(struct sk_buff *skb, u8 *data, unsigned int size)
{
	unsigned int len;
	int retval;

	len = size;
	if (len > skb_tailroom(skb))
		len = skb_tailroom(skb);
	memcpy(__skb_put(skb, len), data, len);

	while ((data += len, size -= len) > 0) {
		skb_frag_t *frag;
		struct page *page;

		if (WARN_ON(skb_shinfo(skb)->nr_frags >= MAX_SKB_FRAGS)) {
			retval = -EMSGSIZE;
			goto out;
		}
		frag = skb_shinfo(skb)->frags + skb_shinfo(skb)->nr_frags;

		page = alloc_page(GFP_ATOMIC);
		if (!page) {
			retval = -ENOMEM;
			goto out;
		}
		__skb_frag_set_page(frag, page);
		len = PAGE_SIZE;
		if (len > size)
			len = size;
		frag->page_offset = 0;
		skb_frag_size_set(frag, len);
		memcpy(skb_frag_address(frag), data, len);

		skb->truesize += len;
		skb->data_len += len;
		skb->len += len;

		skb_shinfo(skb)->nr_frags++;
	}
	retval = 0;
out:
	return retval;
}

static int compress(struct crypto_comp *tfm, bool decompress,
		struct sk_buff *skb)
{
	u8 *scratch = *per_cpu_ptr(compress_scratches, smp_processor_id());
	unsigned int dlen = COMPRESS_SCRATCH_SIZE;
	int retval;

	local_bh_disable();
	if (decompress) {
		retval = crypto_comp_decompress(tfm, skb->data, skb->len,
				scratch, &dlen);
	} else {
		retval = crypto_comp_compress(tfm, skb->data, skb->len,
				scratch, &dlen);
	}
	if (retval == 0) {
		__skb_trim(skb, 0);
		retval = append_data(skb, scratch, dlen);
	}
	local_bh_enable();

	return retval;
}

static unsigned int compress_tg(struct sk_buff *skb,
		const struct xt_action_param *par)
{
	const struct xt_compress_info *compress_info = par->targinfo;
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned int len;
	int retval;
	__be16 new_len;

	if (skb_linearize_cow(skb))
		goto err;
	iph = ip_hdr(skb);

	/**
	 * This check is redundant, since we speficy the dependency on
	 * nf_defrag_ipv4 explicitly in compress_tg_init().
	 */
	if (ip_is_fragment(iph))
		goto err;

	len = par->thoff + sizeof(struct udphdr);
	if (skb->len < len)
		goto err;
	__skb_pull(skb, len);
	retval = compress(compress_info->tfm, compress_info->decompress, skb);
	__skb_push(skb, len);
	if (retval)
		goto err;

	udph = (struct udphdr *)(skb->data + par->thoff);
	len = skb->len - par->thoff;
	udph->len = htons(len);
	if (udph->check) {
		udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, len,
				IPPROTO_UDP, 0);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = (unsigned char *)udph - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
	}

	new_len = htons(skb->len);
	csum_replace2(&iph->check, iph->tot_len, new_len);
	iph->tot_len = new_len;

	return XT_CONTINUE;
err:
	return NF_DROP;
}

static int compress_tg_check(const struct xt_tgchk_param *par)
{
	struct xt_compress_info *compress_info = par->targinfo;
	int len;

	if (compress_info->decompress & ~1)
		return -EINVAL;

	len = strnlen(compress_info->alg_name, sizeof(compress_info->alg_name));
	if (len == 0 || len == ARRAY_SIZE(compress_info->alg_name))
		return -EINVAL;

	compress_info->tfm = crypto_alloc_comp(compress_info->alg_name, 0, 0);
	if (IS_ERR(compress_info->tfm))
		return PTR_ERR(compress_info->tfm);

	return 0;
}

static void compress_tg_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_compress_info *compress_info = par->targinfo;

	crypto_free_comp(compress_info->tfm);
}

static void * __percpu *compress_alloc_scratches(void)
{
	void * __percpu *scratches;
	int i;

	scratches = alloc_percpu(void *);
	if (!scratches)
		goto err;
	for_each_possible_cpu(i) {
		void *scratch;

		scratch = vmalloc_node(COMPRESS_SCRATCH_SIZE, cpu_to_node(i));
		if (!scratch)
			goto err2;
		*per_cpu_ptr(scratches, i) = scratch;
	}

	return scratches;
err2:
	for_each_possible_cpu(i)
		vfree(*per_cpu_ptr(scratches, i));
	free_percpu(scratches);
err:
	return NULL;
}

static void compress_free_scratches(void * __percpu *scratches)
{
	int i;

	for_each_possible_cpu(i)
		vfree(*per_cpu_ptr(scratches, i));
	free_percpu(scratches);
}

static struct xt_target compress_tg_reg __read_mostly = {
	.name		= "COMPRESS",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.proto		= IPPROTO_UDP,
	.target		= compress_tg,
	.targetsize	= sizeof(struct xt_compress_info),
	.checkentry	= compress_tg_check,
	.destroy	= compress_tg_destroy,
	.me		= THIS_MODULE
};

static int __init compress_tg_init(void)
{
	int retval;

	nf_defrag_ipv4_enable();
	compress_scratches = compress_alloc_scratches();
	if (!compress_scratches)
		return -ENOMEM;
	retval = xt_register_target(&compress_tg_reg);
	if (retval) {
		compress_free_scratches(compress_scratches);
		return retval;
	}

	return 0;
}

static void __exit compress_tg_exit(void)
{
	xt_unregister_target(&compress_tg_reg);
	compress_free_scratches(compress_scratches);
}

module_init(compress_tg_init);
module_exit(compress_tg_exit);
